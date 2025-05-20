# SubBrute

A fast and efficient subdomain scanner built in Rust.

## Features

- **High Performance**: Multi-threaded architecture designed for speed
- **Multiple DNS Resolvers**: Uses multiple DNS resolvers in parallel
- **Wildcard Detection**: Automatically detects and filters wildcard DNS responses
- **Flexible Output**: JSON and TXT output options
- **Modern Interface**: Clean progress reporting with colored output

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/Varp0s/subbrute.git
cd subbrute

# Build the project
cargo build --release

# The binary will be in target/release/sub_brute
```

### Using Docker

```bash
# Build the Docker image
docker build -t subbrute .

# Run the container
docker run --rm subbrute -d example.com -w /app/test-list.txt

# Using a custom wordlist with output to the host system
docker run --rm -v $(pwd):/output subbrute -d example.com -w /app/wordlists/common.txt -o json

# Using Docker Compose (edit docker-compose.yml for your settings)
docker-compose up
```

For Windows users, a PowerShell script is provided for convenience:

```powershell
# Run with default settings
.\docker-run.ps1

# Run with custom domain and wordlist
.\docker-run.ps1 example.com /app/wordlists/common.txt 75 json
```

## Usage

```bash
# Basic usage
./sub_brute -d example.com -w wordlist.txt

# With custom thread count
./sub_brute -d example.com -w wordlist.txt -t 50

# Output results to a file (json or txt)
./sub_brute -d example.com -w wordlist.txt -o json
```

### Command-Line Options

- `-d, --domain <DOMAIN>`: Target domain to scan
- `-w, --wordlist <WORDLIST>`: Path to the wordlist file
- `-t, --threads <THREADS>`: Number of threads (default: 15)
- `-o, --output <FORMAT>`: Output format (json or txt)

## Performance Tips

- Use a larger thread count for faster scanning (`-t 50` or higher if your system allows)
- For best performance, run on systems with good network connectivity
- Larger wordlists will take longer but may find more subdomains

## Included Wordlists

The project includes a small set of common subdomain wordlists:

- `wordlists/common.txt` - Basic common subdomains (small, good for testing)
- `test-list.txt` - Minimal list for quick tests

For production use, consider using larger wordlists from sources like:
- SecLists: https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS
- Assetnote: https://wordlists.assetnote.io/

## License

MIT

## Author

Developed by Varp0s
