# SSL Verifier

## Run locally

### Build 
`make build`

### Running
Single url
`make run-single url=<url to test>`

For instance: `make run-single url=example.com`

Batch of urls from json file (Example json in `/examples`)

`make run-batch input=<path_to_input_file> output=<path_to_output_file>`

For instance: `make run-batch input=examples/test_urls.json output=test-results.json`
