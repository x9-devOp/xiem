using System.Security.Cryptography;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace XiemAgent;

/// <summary>
/// Verifies RSA-PSS-SHA256 signatures on commands received from the server.
/// Public key is downloaded at registration and pinned to disk.
/// Canonical message format: "{command_id}:{command_type}:{compact_sorted_json_payload}"
/// </summary>
public class SignatureVerifier
{
    private readonly ILogger<SignatureVerifier> _log;
    private RSA? _key;

    private static readonly string PubKeyFile = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "XiemAgent", "server_pubkey.pem");

    // UnsafeRelaxedJsonEscaping matches Python json.dumps behavior:
    // apostrophes and HTML chars are NOT escaped to \uXXXX.
    private static readonly JsonSerializerOptions CompactOpts = new()
    {
        WriteIndented = false,
        PropertyNamingPolicy = null,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    public bool IsLoaded => _key != null;

    public SignatureVerifier(ILogger<SignatureVerifier> log)
    {
        _log = log;
        TryLoadFromDisk();
    }

    public void LoadFromPem(string pem)
    {
        try
        {
            var key = RSA.Create();
            key.ImportFromPem(pem);
            _key = key;
            SaveToDisk(pem);
            _log.LogInformation("Server public key loaded and pinned to disk");
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Failed to load server public key from PEM");
        }
    }

    /// <summary>
    /// Returns true if signature is valid. Returns false and logs if invalid.
    /// If no public key is loaded, logs a warning and returns false.
    /// </summary>
    public bool Verify(int commandId, string commandType, Dictionary<string, object?> payload, string? signatureBase64)
    {
        if (_key == null)
        {
            _log.LogWarning("Cannot verify command {Id}: no server public key loaded", commandId);
            return false;
        }

        if (string.IsNullOrEmpty(signatureBase64))
        {
            _log.LogWarning("Command {Id} has no signature — rejected", commandId);
            return false;
        }

        try
        {
            var canonical = $"{commandId}:{commandType}:{SerializeCanonical(payload)}";
            var messageBytes = Encoding.UTF8.GetBytes(canonical);
            var signature = Convert.FromBase64String(signatureBase64);

            // Salt length = 32 (SHA256 digest size) — matches Python cryptography PSS.DIGEST_LENGTH
            var valid = _key.VerifyData(
                messageBytes, signature,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pss
            );

            if (!valid)
                _log.LogWarning("Command {Id} signature INVALID — rejecting", commandId);

            return valid;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Signature verification error for command {Id}", commandId);
            return false;
        }
    }

    // Sort top-level keys lexicographically (matches Python json.dumps sort_keys=True).
    // Values are JsonElement after deserialization and serialize as their raw JSON.
    private static string SerializeCanonical(Dictionary<string, object?> payload)
    {
        var sorted = new SortedDictionary<string, object?>(payload, StringComparer.Ordinal);
        return JsonSerializer.Serialize(sorted, CompactOpts);
    }

    private void TryLoadFromDisk()
    {
        try
        {
            if (!File.Exists(PubKeyFile)) return;
            var pem = File.ReadAllText(PubKeyFile);
            var key = RSA.Create();
            key.ImportFromPem(pem);
            _key = key;
            _log.LogInformation("Server public key loaded from disk");
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Failed to load server public key from disk");
        }
    }

    private void SaveToDisk(string pem)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(PubKeyFile)!);
            File.WriteAllText(PubKeyFile, pem);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Failed to save server public key to disk");
        }
    }
}
