package main

import (
	"log"

	"github.com/zero-day-ai/sdk/serve"
)

func main() {
	tool := NewTool()
	if err := serve.Tool(tool); err != nil {
		log.Fatal(err)
	}
}
