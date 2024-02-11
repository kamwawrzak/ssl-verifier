package server

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/kamwawrzak/sslverifier/internal/model"
)

type certVerifier interface {
	Verify(string) (*model.Result, error)
}

type verifyHandler struct {
	verifier certVerifier
}

func NewVerifyHandler(verifier certVerifier) *verifyHandler {
	return &verifyHandler{
		verifier: verifier,
	}
}

type requestInput struct {
	Urls []string `json:"urls"`
}

type response struct {
	Results []*model.Result `json:"results"`
}


func (h *verifyHandler) verifyCertificate(w http.ResponseWriter, r *http.Request) {
	var input requestInput
	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		http.Error(w, fmt.Sprintf("Failed to decode JSON: %v", err), http.StatusBadRequest)
		return
	}
	var results []*model.Result
	for _, url := range input.Urls {
		res, err := h.verifier.Verify(url)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to verify certificate: %v", err), http.StatusInternalServerError)
			return
		}
		results = append(results, res)
	}
	
	resp := response{
		Results: results,
	}

	err := json.NewEncoder(w).Encode(resp)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to verify certificate: %v", err), http.StatusInternalServerError)
		return
	}
}