package main

import (
	"fmt"
	"os"

	"github.com/btcsuite/btcutil/base58"
)

func main() {
	my_pk := "z8ne6htdQaJkE7aaEPvTGZXNt7HDaxjPrgHhTWEX1gnq6ea7vo1WQLMRqfUBws3JZmBgA916aaPic9zcpgUfUZf"
	encoding := base58.FlickrEncoding // or RippleEncoding or BitcoinEncoding

	encoded, err := encoding.Encode([]byte("100"))
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	fmt.Println(string(encoded))

	decoded, err := encoding.Decode(encoded)
	if err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
	fmt.Println(string(decoded))
}
