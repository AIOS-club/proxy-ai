package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type OpenAIRequest struct {
	APIKey string `json:"api_key"`
	Path   string `json:"path"`
	Method string `json:"method"`
	// Other OpenAI request parameters
}

type ErrorResponse struct {
	Error struct {
		Message string      `json:"message"`
		Type    string      `json:"type"`
		Param   interface{} `json:"param"`
		Code    interface{} `json:"code"`
	} `json:"error"`
}

var allowedIPs []string

const (
	openAIURL = "https://api.openai.com/v1"
)

func main() {
	// Get the allowedIPs list from the environment variables. If not set, allow all IPs by default.
	allowedIPsStr := os.Getenv("ALLOWED_IPS")
	if allowedIPsStr == "" {
		allowedIPsStr = "*"
	}

	for _, ipStr := range strings.Split(allowedIPsStr, ",") {
		allowedIPs = append(allowedIPs, strings.TrimSpace(ipStr))
	}

	http.HandleFunc("/openai/v1", openaiHandler)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		errorResponse(w, fmt.Sprintf("Invalid URL %s", r.URL.Path), "not_found", http.StatusNotFound)
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func openaiHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		errorResponse(w, "Invalid method", "method_not_allowed", http.StatusMethodNotAllowed)
		return
	}

	start := time.Now()

	// Get the IP address of the request
	ip := getIPAddress(r)

	// Get the request ID
	requestID := r.Header.Get("x-fc-request-id")
	if requestID == "" {
		requestID = genUUID()
	}

	// Check if the requested IP is in the allowed list
	if !isAllowedIP(ip) {
		log.Printf("[ERROR] %s %s Unauthorized request from IP: %s\n", ip, requestID, ip)
		errorResponse(w, "Unauthorized request", "forbidden", http.StatusForbidden)
		return
	}

	// Read the body of the original request
	requestBody, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("[ERROR] %s %s Failed to read request body: %v\n", ip, requestID, err)
		errorResponse(w, "Internal Server Error", "internal_server_error", http.StatusInternalServerError)
		return
	}

	// Parse OpenAIRequest
	var openaiReq OpenAIRequest
	if err := json.Unmarshal(requestBody, &openaiReq); err != nil {
		log.Printf("[ERROR] %s %s Failed to unmarshal OpenAIRequest: %v\n", ip, requestID, err)
		errorResponse(w, "Failed to unmarshal request json", "bad_request", http.StatusBadRequest)
		return
	}

	// Verify request parameters
	if openaiReq.APIKey == "" || openaiReq.Path == "" || openaiReq.Method == "" {
		log.Printf("[ERROR] %s %s Missing required parameters, api_key, path, method\n", ip, requestID)
		errorResponse(w, "Missing required parameters, api_key, path, method", "bad_request", http.StatusBadRequest)
		return
	}

	// Construct the body of the forwarded request
	var openaiReqBody map[string]interface{}
	if err := json.Unmarshal(requestBody, &openaiReqBody); err != nil {
		log.Printf("[ERROR] %s %s Failed to unmarshal OpenAIRequest body: %v\n", ip, requestID, err)
		errorResponse(w, "Internal Server Error", "internal_server_error", http.StatusInternalServerError)
		return
	}

	delete(openaiReqBody, "api_key")
	delete(openaiReqBody, "path")
	delete(openaiReqBody, "method")
	openaiReqBodyBytes, err := json.Marshal(openaiReqBody)
	if err != nil {
		log.Printf("[ERROR] %s %s Failed to marshal OpenAIRequest body: %v\n", ip, requestID, err)
		errorResponse(w, "Internal Server Error", "internal_server_error", http.StatusInternalServerError)
		return
	}

	// Get the full content of the client request body
	requestBodyStr := string(requestBody)

	// Construct the forwarded request
	openaiURL := openAIURL + openaiReq.Path
	req, err := http.NewRequest(openaiReq.Method, openaiURL, bytes.NewBuffer(openaiReqBodyBytes))
	if err != nil {
		log.Printf("[ERROR] %s %s Failed to create OpenAI request: %v\n", ip, requestID, err)
		errorResponse(w, "Internal Server Error", "internal_server_error", http.StatusInternalServerError)
		return
	}

	// Add the API key of the request to the heade
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", openaiReq.APIKey))
	req.Header.Set("Content-Type", "application/json")

	// Forward request to OpenAI
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[ERROR] %s %s Failed to send request to OpenAI: %v\n", ip, requestID, err)
		errorResponse(w, "Internal Server Error", "internal_server_error", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	// Read the response from OpenAI
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("[ERROR] %s %s Failed to read OpenAI response: %v\n", ip, requestID, err)
		errorResponse(w, "Internal Server Error", "internal_server_error", http.StatusInternalServerError)
		return
	}

	// Return the response and status code of the forwarded request
	w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
	w.WriteHeader(resp.StatusCode)
	w.Write(responseBody)

	// Record request logs
	log.Printf("[INFO] %s %s (%vms) Request: %s Response: [%v] %s\n", ip, requestID, time.Since(start).Milliseconds(), minifyJSONToSingleLine(requestBodyStr), resp.StatusCode, minifyJSONToSingleLine(string(responseBody)))
}

// Get the IP address
func getIPAddress(r *http.Request) string {
	ip := r.Header.Get("X-Real-Ip")
	if ip == "" {
		ip = r.Header.Get("X-Forwarded-For")
		if ip == "" {
			ip, _, _ = net.SplitHostPort(r.RemoteAddr)
		}
	}
	return ip
}

// Check if the requested IP is in the allowed list
func isAllowedIP(ip string) bool {
	for _, allowedIP := range allowedIPs {
		if allowedIP == "*" || allowedIP == ip {
			return true
		}
	}
	return false
}

// Encapsulate error returns in the format of OpenAI errors
func errorResponse(w http.ResponseWriter, respMsg string, httpStatus string, httpStatusCode int) {
	errResp := ErrorResponse{
		struct {
			Message string      `json:"message"`
			Type    string      `json:"type"`
			Param   interface{} `json:"param"`
			Code    interface{} `json:"code"`
		}{
			Message: respMsg,
			Type:    httpStatus,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatusCode)
	json.NewEncoder(w).Encode(errResp)
}

// Minify a JSON string to a single line.
func minifyJSONToSingleLine(jsonStr string) string {
	var jsonObj interface{}
	if err := json.Unmarshal([]byte(jsonStr), &jsonObj); err != nil {
		return jsonStr
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, []byte(jsonStr)); err != nil {
		return jsonStr
	}
	return buf.String()
}

// Generate a lightweight UUID
func genUUID() string {
	uuid := make([]byte, 16)
	_, err := rand.Read(uuid)
	if err != nil {
		panic(err)
	}

	// Set UUID version and variant
	uuid[8] = uuid[8]&^0xc0 | 0x80 // Version number is 4
	uuid[6] = uuid[6]&^0xf0 | 0x40 // Variant is standard format

	// Convert UUID byte array to string
	str := hex.EncodeToString(uuid)

	// Insert hyphens "-" at positions 8, 13, 18, and 23
	return strings.Join([]string{str[:8], str[8:12], str[12:16], str[16:20], str[20:]}, "-")
}
