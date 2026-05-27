# Installation

## Homebrew (macOS/Linux)

```bash
brew tap cliffcolvin/helmscan
brew install helmscan
```

## Binary Download

Download the latest release for your platform from [GitHub Releases](https://github.com/cliffcolvin/helmscan/releases):

### macOS
```bash
# Intel
curl -L https://github.com/cliffcolvin/helmscan/releases/latest/download/helmscan_Darwin_x86_64.tar.gz | tar xz
sudo mv helmscan /usr/local/bin/

# Apple Silicon
curl -L https://github.com/cliffcolvin/helmscan/releases/latest/download/helmscan_Darwin_arm64.tar.gz | tar xz
sudo mv helmscan /usr/local/bin/
```

### Linux
```bash
curl -L https://github.com/cliffcolvin/helmscan/releases/latest/download/helmscan_Linux_x86_64.tar.gz | tar xz
sudo mv helmscan /usr/local/bin/
```

### Windows
Download `helmscan_Windows_x86_64.zip` from releases and extract to your PATH.

## From Source

```bash
go install github.com/cliffcolvin/helmscan/cmd/app@latest
```

## Verify Installation

```bash
helmscan --version