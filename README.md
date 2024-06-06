# Espresso Sequencer Transactions Decoder

This project is used to decode the transactions of the Espresso Sequencer, which is located at [0xFdBF8b5Ed2c16650aa835315a67d83Eda5c98872](https://sepolia.etherscan.io/address/0xfdbf8b5ed2c16650aa835315a67d83eda5c98872) on Sepolia Ethereum.

## Usage

To utilize this tool, you need to follow these instructions:

1. Clone this repository to your local machine.
2. Navigate to the cloned directory.
3. Open the `main.go` file.
4. Find a transaction to decode from the Espresso Sequencer, specifically an input field from the `newFinalizeTransaction` method.
5. Copy this input field and paste it in the `main.go` where indicated.
6. Save the `main.go` file and run it using the command `go run main.go`.

The program will then decode the provided transaction input and print the result to the console. Please ensure that Go SDK 1.22.3 and Go programming language version 1.22 are installed on your system.

## Contributing

If you have any suggestions or find any bugs, please create an issue in the repository. Contributions are more than welcome.

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.