# Homebrew formula for ClawSentry
# To use: brew tap Elroyper/clawsentry && brew install clawsentry

class Clawsentry < Formula
  include Language::Python::Virtualenv

  desc "AHP safety supervision framework for AI coding agents"
  homepage "https://elroyper.github.io/ClawSentry/"
  url "https://files.pythonhosted.org/packages/source/c/clawsentry/clawsentry-0.6.3.tar.gz"
  sha256 "896bca4df3a96703fb3d16b087d3576da930dfb3d67de71579f5fa38f2e4e70e"
  license "MIT"
  head "https://github.com/Elroyper/ClawSentry.git", branch: "main"

  depends_on "python@3.12"

  def install
    virtualenv_create(libexec, "python3.12")
    system libexec/"bin/pip", "install", "--no-cache-dir", cached_download
    # Link CLI entry points
    %w[clawsentry clawsentry-gateway clawsentry-harness clawsentry-stack].each do |cmd|
      bin.install_symlink libexec/"bin/#{cmd}"
    end
  end

  def caveats
    <<~EOS
      ClawSentry CLI commands installed:
        clawsentry          — unified entry point
        clawsentry-gateway  — supervision gateway server
        clawsentry-harness  — hook harness (stdio adapter)
        clawsentry-stack    — all-in-one stack launcher

      Quick start:
        clawsentry init claude-code   # or: a3s-code / codex / openclaw
        clawsentry start

      Documentation: https://elroyper.github.io/ClawSentry/
    EOS
  end

  test do
    assert_match "clawsentry", shell_output("#{bin}/clawsentry --help 2>&1")
    assert_match version.to_s,
                 shell_output("#{bin}/clawsentry-gateway --version 2>&1")
  end
end
