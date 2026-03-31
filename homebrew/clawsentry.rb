# Homebrew formula for ClawSentry
# To use: brew tap Elroyper/clawsentry && brew install clawsentry
#
# STATUS: Experimental — formula skeleton only.
# The full resource blocks (20+ Python deps) need to be generated with:
#   brew update-python-resources clawsentry
# after installing: pip install homebrew-pypi-poet
#
# For reliable installation, use: pip install clawsentry  OR  uv tool install clawsentry

class Clawsentry < Formula
  include Language::Python::Virtualenv

  desc "AHP safety supervision framework for AI coding agents"
  homepage "https://elroyper.github.io/ClawSentry/"
  url "https://files.pythonhosted.org/packages/source/c/clawsentry/clawsentry-0.3.1.tar.gz"
  sha256 "PLACEHOLDER_UPDATE_ON_RELEASE"
  license "MIT"
  head "https://github.com/Elroyper/ClawSentry.git", branch: "main"

  depends_on "python@3.12"

  def install
    virtualenv_install_with_resources
  end

  test do
    system bin/"clawsentry", "--help"
  end
end
