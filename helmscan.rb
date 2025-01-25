class Helmscan < Formula
  desc "A tool for scanning Helm charts for vulnerabilities"
  homepage "https://github.com/cliffcolvin/helmscan"
  version "0.1.0"

  # Dependencies
  depends_on "helm"
  depends_on "aquasecurity/trivy/trivy"
  depends_on "yq"
  depends_on "jq"

  if OS.mac? && Hardware::CPU.arm?
    url "https://github.com/cliffcolvin/helmscan/releases/download/v0.1.0/helmscan_Darwin_arm64.tar.gz"
    sha256 "..." # Replace with actual SHA256 of your ARM64 binary
  elsif OS.mac? && Hardware::CPU.intel?
    url "https://github.com/cliffcolvin/helmscan/releases/download/v0.1.0/helmscan_Darwin_x86_64.tar.gz"
    sha256 "..." # Replace with actual SHA256 of your AMD64 binary
  elsif OS.linux? && Hardware::CPU.intel?
    url "https://github.com/cliffcolvin/helmscan/releases/download/v0.1.0/helmscan_Linux_x86_64.tar.gz"
    sha256 "..." # Replace with actual SHA256 of your Linux AMD64 binary
  end

  def install
    bin.install "helmscan"
  end

  test do
    system "#{bin}/helmscan", "--version"
  end
end
