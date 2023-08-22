# BTC InfoStar

![BTC InfoStar Logo](logo.png)

BTC InfoStar is a versatile Python tool designed to simplify the generation, processing, and analysis of Bitcoin key pairs. This tool offers a diverse range of features, enabling users to securely generate, store, sort, and analyze Bitcoin addresses and keys.

## Key Features

- **Key Generation:** BTC InfoStar allows you to generate a sequence of private keys, either in ascending order or randomly. Users can define the range of private keys to generate a specific number of keys.

- **Hexadecimal to Integer Conversion:** The tool provides a feature to convert hexadecimal values to integers, aiding in understanding the numeric representation of Bitcoin keys.

- **Random Key Generation:** BTC InfoStar facilitates the random creation of private keys within a specified range. This is useful for scenarios requiring a multitude of random keys.

- **Mnemonic Generation:** The tool can generate mnemonic words that can be used to recover a Bitcoin key. It supports generating mnemonics of varying lengths (12, 15, 18, and 24 words).

- **Sorting Key Data:** BTC InfoStar offers functionalities to sort key data into JSON files based on various criteria, such as hexadecimal values, integers, or WIF (Wallet Import Format).

- **Generation Based on Public Key Range:** The tool can generate private keys based on a specific range of public keys. This is helpful for finding keys corresponding to a particular group of addresses.

## Usage

1. Clone this repository to your local machine.
2. Run the `btc_infostar.py` script to access the tool's features.
   - Before using options 1 and 3, you need to convert your hexadecimal private key to an integer in option 2, which you can then use in options 1 and 3.
3. Follow the on-screen prompts to generate, analyze, and store Bitcoin key data.

## Personal Note

Creating and refining BTC InfoStar has been a journey of dedication and learning. It's been weeks of effort and countless iterations to bring this tool to life. I'm thrilled to share it with the community and hope it proves valuable to fellow Bitcoin enthusiasts, developers, and researchers.

I would like to extend a special thanks to [Mizogg](https://github.com/GitHubUsername) for their invaluable assistance and contributions to this project. Your insights and expertise have greatly shaped BTC InfoStar. Additionally, I want to express my deep appreciation to [Iceland2k14](https://github.com/iceland2k14) for their exceptional work on the [secp256k1](https://github.com/iceland2k14/secp256k1) library that forms the foundation of this tool.

## Contribution

Contributions to BTC InfoStar are welcome! Feel free to fork this repository, make improvements, and submit pull requests.

## Donations

If you find BTC InfoStar useful, consider making a donation:

- BTC: bc1qtkxuklcps9tf8hmgy8l62f5k8h3v2myduea68k
- ETH: 0x75c89c885CcddD181feaFA272351C87005CE7Afb

## License

BTC InfoStar is open-source software released under the [MIT License](LICENSE).
