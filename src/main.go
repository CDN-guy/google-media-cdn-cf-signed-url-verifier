package main

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm"
	"github.com/proxy-wasm/proxy-wasm-go-sdk/proxywasm/types"
)

// Main entry point for the Wasm module.
func main() {}

func init() {
	proxywasm.SetVMContext(&vmContext{})
}

// vmContext handles the plugin's lifecycle.
type vmContext struct {
	types.DefaultVMContext
}

// pluginContext holds the configuration for the plugin, in this case, the public key.
type pluginContext struct {
	types.DefaultPluginContext
	publicKey *rsa.PublicKey
}

// httpContext handles the logic for a single HTTP request.
type httpContext struct {
	types.DefaultHttpContext
	publicKey *rsa.PublicKey
}

// NewPluginContext is called when the plugin is configured.
func (*vmContext) NewPluginContext(uint32) types.PluginContext {
	return &pluginContext{}
}

// NewHttpContext is called for each new HTTP request.
func (p *pluginContext) NewHttpContext(uint32) types.HttpContext {
	return &httpContext{publicKey: p.publicKey}
}

// OnPluginStart is called when the plugin is first loaded and configured.
func (p *pluginContext) OnPluginStart(pluginConfigurationSize int) types.OnPluginStartStatus {
	config, err := proxywasm.GetPluginConfiguration()
	if err != nil {
		proxywasm.LogCriticalf("failed to get plugin configuration: %v", err)
		return types.OnPluginStartStatusFailed
	}
	block, _ := pem.Decode(config)
	if block == nil {
		proxywasm.LogCritical("failed to decode PEM block")
		return types.OnPluginStartStatusFailed
	}

	var pub interface{}
	pub, err = x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		pub, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			proxywasm.LogCriticalf("failed to parse public key: %v", err)
			return types.OnPluginStartStatusFailed
		}
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		proxywasm.LogCritical("public key is not RSA")
		return types.OnPluginStartStatusFailed
	}

	p.publicKey = rsaPub
	proxywasm.LogInfof("public key configured successfully")
	return types.OnPluginStartStatusOK

}

// OnHttpRequestHeaders is the main entry point for request validation.
func (h *httpContext) OnHttpRequestHeaders(numHeaders int, endOfStream bool) types.Action {
	// Reconstruct the full URL from the request headers
	scheme, err := proxywasm.GetHttpRequestHeader(":scheme")
	if err != nil {
		proxywasm.LogWarnf("failed to get :scheme header: %v", err)
		proxywasm.SendHttpResponse(400, nil, []byte("Bad Request: missing scheme"), -1)
		return types.ActionPause
	}

	authority, err := proxywasm.GetHttpRequestHeader(":authority")
	if err != nil {
		proxywasm.LogWarnf("failed to get :authority header: %v", err)
		proxywasm.SendHttpResponse(400, nil, []byte("Bad Request: missing authority"), -1)
		return types.ActionPause
	}

	path, err := proxywasm.GetHttpRequestHeader(":path")
	if err != nil {
		proxywasm.LogWarnf("failed to get :path header: %v", err)
		proxywasm.SendHttpResponse(400, nil, []byte("Bad Request: missing path"), -1)
		return types.ActionPause
	}

	fullURL := fmt.Sprintf("%s://%s%s", scheme, authority, path)
	proxywasm.LogInfof("Verifying URL: %s", fullURL)

	// Call the verifyCloudFrontSignedURL() function with the parsed public key
	isValid, err := verifyCloudFrontSignedURL(fullURL, h.publicKey)
	if err != nil {
		proxywasm.LogErrorf("error during signature verification: %v", err)
		errMsg := fmt.Sprintf("error: %s", err.Error())
		proxywasm.SendHttpResponse(403, nil, []byte(errMsg), -1)
		return types.ActionPause
	}

	if !isValid {
		proxywasm.LogWarnf("Failed CloudFront signature verification for URL: %s", fullURL)
		proxywasm.SendHttpResponse(403, nil, []byte("Verification Error: Invalid Signature."), -1)
		return types.ActionPause
	}

	// If valid, remove the signed URL parameters, let the request continue to the upstream service
	proxywasm.LogInfo("Successfully verified CloudFront signature.Removing signed URL parameters from path.")
	
	// Use url.Parse to safely manipulate the query string. A dummy base is not
	// needed since path is already a valid request URI.
	parsedPath, err := url.Parse(path)
	if err != nil {
		proxywasm.LogErrorf("Could not parse path '%s' for modification: %v", path, err)
		// Fail closed if we can't parse a path that we previously used.
		proxywasm.SendHttpResponse(500, nil, []byte("error: could not parse path for modification"), -1)
		return types.ActionPause
	}
	
	queryParams := parsedPath.Query()
	queryParams.Del("Policy")
	queryParams.Del("Signature")
	queryParams.Del("Expires")
	queryParams.Del("Key-Pair-Id")
	
	// Re-encode the query parameters and get the final path.
	parsedPath.RawQuery = queryParams.Encode()
	newPath := parsedPath.String()
	
	// Replace the original :path header with the cleaned one.
	if err := proxywasm.ReplaceHttpRequestHeader(":path", newPath); err != nil {
		proxywasm.LogErrorf("Failed to replace :path header: %v", err)
		proxywasm.SendHttpResponse(500, nil, []byte("error: failed to modify request path"), -1)
		return types.ActionPause
	}
	proxywasm.LogInfof("Path modified to: %s", newPath)

	return types.ActionContinue
}

// -----------------------------------------------------------------------------
// CloudFront Signed-URL Verification Function
// -----------------------------------------------------------------------------

// Structs to unmarshal CloudFront's custom policy JSON
type AWSEpochTime struct {
	EpochTime int64 `json:"AWS:EpochTime"`
}

type Condition struct {
	DateLessThan AWSEpochTime `json:"DateLessThan"`
}

type Statement struct {
	Resource  string    `json:"Resource"`
	Condition Condition `json:"Condition"`
}

type Policy struct {
	Statements []Statement `json:"Statement"`
}

func verifyCloudFrontSignedURL(signedURL string, rsaPub *rsa.PublicKey) (bool, error) {
	if rsaPub == nil {
		return false, errors.New("bad public key: nil")
	}

	parsedURL, err := url.Parse(signedURL)
	if err != nil {
		return false, fmt.Errorf("Failed to parse URL: %w", err)
	}
	queryParams := parsedURL.Query()

	signatureB64 := queryParams.Get("Signature")
	if signatureB64 == "" {
		return false, errors.New("URL is missing the 'Signature' parameter.")
	}
	// CloudFront uses a URL-safe base64 encoding, so we need to replace some characters.
	// https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-creating-signed-url-canned-policy.html
	replacer := strings.NewReplacer("-", "+", "_", "=", "~", "/")
	signature, err := base64.StdEncoding.DecodeString(replacer.Replace(signatureB64))
	if err != nil {
		return false, fmt.Errorf("Invalid 'Signature' parameter.")
	}

	var policyStr string
	var expirationTime int64

	if policyB64 := queryParams.Get("Policy"); policyB64 != "" {
		// Using a Custom Policy
		decodedPolicy, err := base64.StdEncoding.DecodeString(replacer.Replace(policyB64))
		if err != nil {
			return false, fmt.Errorf("Failed to decode custom policy.")
		}
		policyStr = string(decodedPolicy)
		var policyData Policy
		if err := json.Unmarshal(decodedPolicy, &policyData); err != nil {
			return false, fmt.Errorf("Failed to parse policy JSON.")
		}
		if len(policyData.Statements) == 0 {
			return false, errors.New("Policy has no statements.")
		}
		expirationTime = policyData.Statements[0].Condition.DateLessThan.EpochTime
	} else if expiresStr := queryParams.Get("Expires"); expiresStr != "" {
		// Using a Canned Policy
		expirationTime, err = strconv.ParseInt(expiresStr, 10, 64)
		if err != nil {
			return false, fmt.Errorf("Failed to parse 'Expires' parameter.")
		}
		// Construct the policy string that CloudFront would have used to sign this.
		resourceURL := parsedURL.Scheme + "://" + parsedURL.Host + parsedURL.Path
		policy := Policy{
			Statements: []Statement{
				{
					Resource: resourceURL,
					Condition: Condition{
						DateLessThan: AWSEpochTime{EpochTime: expirationTime},
					},
				},
			},
		}
		policyBytes, err := json.Marshal(policy)
		if err != nil {
			return false, fmt.Errorf("Failed to marshal canned policy to JSON.")
		}
		policyStr = string(policyBytes)
	} else {
		return false, errors.New("URL has neither 'Policy' nor 'Expires'")
	}

	// Hash the policy string
	hasher := sha1.New()
	hasher.Write([]byte(policyStr))
	hashed := hasher.Sum(nil)

	// Verify the signature against the hashed policy
	err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA1, hashed, signature)
	if err != nil {
		proxywasm.LogInfof("Signature verification failed.")
		return false, errors.New("Invalid signature.")
		//return false, nil // A verification failure is not a server error
	}

	// Check if the URL has expired
	if time.Now().Unix() > expirationTime {
		proxywasm.LogInfo("URL has expired.")
		return false, errors.New("URL has expired.")
		//return false, nil
	}

	return true, nil
}

