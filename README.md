# SSL Verifier

## Run locally

### Build server and cli binary
`make build-all`

### Running as HTTP server
**On localhost**
Run on default port 8080
`make run-server`

If you want to change port use:
`make run-server port=<port>`

Example request for localhost:
`curl -X POST -d '{"urls": ["example.com", "https://google.com"]}' localhost:8080/verify`

### Running as CLI
* Single url
`make run-single url=<url to test>`

For instance: `make run-single url=example.com`

* Batch of urls from json file (Example json in `/examples`)

`make run-batch input=<path_to_input_file> output=<path_to_output_file>`

For instance: `make run-batch input=examples/test_urls.json output=test-results.json`
