package models

// Known error messages from the API
const (
	InvalidPublicKey = "Invalid public key"
)

type APIError struct {
	// not sure what type this is, so we will settle for interface{}
	// for now
	Result   interface{} `json:"result"`
	Success  bool        `json:"success"`
	Errors   []ErrorInfo `json:"errors"`
	Messages []string    `json:"messages"`
}

type ErrorInfo struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ErrorsAsString returns a string representation of the errors in the APIError.
// It concatenates the error messages into a single string, separated by semicolons.
//
// Parameters:
//   - separator: string - The string to use as a separator between error messages.
//
// Returns:
//   - string: A string containing all error messages, separated by the specified separator.
func (e *APIError) ErrorsAsString(separator string) string {
	var result string
	for _, err := range e.Errors {
		result += err.Message + separator
	}
	if len(result) > 0 {
		return result[:len(result)-len(separator)]
	}
	return result
}

// HasErrorMessage checks if the APIError contains a specific error message.
// It returns true if the error message is found, otherwise false.
//
// Parameters:
//   - message: string - The error message to check for.
//
// Returns:
//   - bool: true if the error message is found, otherwise false.
func (e *APIError) HasErrorMessage(message string) bool {
	for _, err := range e.Errors {
		if err.Message == message {
			return true
		}
	}
	return false
}
