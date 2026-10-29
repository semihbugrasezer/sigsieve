# DRAFT - NOT PUBLISHED. Not in homebrew-core or any tap; publishing requires
# maintainer approval. SigSieve is an experimental, unaudited alpha.
# See packaging/homebrew/README.md before changing url/sha256.
class Sigsieve < Formula
  desc "SSH agent filtering proxy that exposes only allowlisted identities"
  homepage "https://github.com/semihbugrasezer/sigsieve"
  # Source archive of the immutable tag (commit fc7484be0371242f517b6628b0f7dcc3a9a12a29).
  url "https://github.com/semihbugrasezer/sigsieve/archive/refs/tags/v0.1.0-alpha.2.tar.gz"
  sha256 "a05994e71a165d5b1759c4cad2528aab2a02269bc7db85164359dec4829977a7"
  license "MIT"

  # No `head` block on purpose: it would build untagged `main`.

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
  end

  test do
    ENV.delete "SSH_AUTH_SOCK"
    ENV.delete "SIGSIEVE_UPSTREAM"
    ENV.delete "SIGSIEVE_ALLOW"
    ENV.delete "SIGSIEVE_DESTINATIONS"

    assert_match "sigsieve #{version}", shell_output("#{bin}/sigsieve --version")

    # No real agent: an unreachable upstream must fail (exit 1), not pass.
    output = shell_output("#{bin}/sigsieve doctor --upstream #{testpath}/missing.sock", 1)
    assert_match "Upstream agent:     FAIL", output

    # A malformed allowlist entry is a configuration error (exit 2).
    output = shell_output("#{bin}/sigsieve doctor --upstream #{testpath}/missing.sock " \
                          "--allow-fingerprint not-a-fingerprint", 2)
    assert_match "Configuration:      INVALID", output
  end
end
