package service

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetHostAndPort(t *testing.T) {
	// arrange
	testCases := []struct{
		input string
		expectedHost string
		expectedPort string
		expectedErr error
	}{
		{
			"example.com",
			"example.com",
			"",
			nil,
		},
		{
			"example.com:80",
			"example.com",
			"80",
			nil,
		},
		{
			"https://example.com",
			"example.com",
			"",
			nil,
		},
		{
			"https://example.com:80",
			"example.com",
			"80",
			nil,
		},
		{
			urlWithCtrlCharacter("http://example.com"),
			"",
			"",
			fmt.Errorf("failed to parse URL: http://example.com\x7f"),
		},
	}
	
	

	for _, tc := range testCases {
		// act
		aHost, aPort, err := getHostAndPort(tc.input)
		
		// assert
		assert.Equal(t, tc.expectedErr, err)
		assert.Equal(t, tc.expectedHost, aHost)
		assert.Equal(t, tc.expectedPort, aPort)
	}

}

func TestHasScheme(t *testing.T){
	// arrange
	testCases := []struct{
		input string
		expected bool
	}{
		{
			"https://example.com",
			true,
		},
		{
			"example.com",
			false,
		},
	}

	for _, tc := range testCases {
		// act
		actual := hasScheme(tc.input)

		// assert
		assert.Equal(t, tc.expected, actual)
	}
}

func TestGetTargetAddress(t *testing.T) {
	// arrange

	testCases := []struct{
		input string
		expected string
		err error
	}{
		{
			"example.com",
			"example.com:443",
			nil,
		},
		{
			"example.com:80",
			"example.com:80",
			nil,
		},
		{
			"https://example.com",
			"example.com:443",
			nil,
		},
		{
			"https://example.com:80",
			"example.com:80",
			nil,
		},
		{
			urlWithCtrlCharacter("https://example.com"),
			"",
			fmt.Errorf("failed to parse URL: https://example.com\x7f"),
		},
	}

	for _, tc := range testCases {
		// act
		actual, err := getTargetAddress(tc.input)

		// assert
		assert.Equal(t, tc.err, err)
		assert.Equal(t, tc.expected, actual)
	}
}

func urlWithCtrlCharacter(url string) string {
	bytes := []byte(url)
	bytes = append(bytes, 0x7f)
	return string(bytes)
}