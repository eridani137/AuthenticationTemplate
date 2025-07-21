using QRCoder;

namespace AuthenticationTemplate.Core.Extensions;

public static class QrCodeExtensions
{
    public static string GenerateQrCodeBase64(this string totpUri)
    {
        using var qrGenerator = new QRCodeGenerator();
        var qrCodeData = qrGenerator.CreateQrCode(totpUri, QRCodeGenerator.ECCLevel.Q);
        
        using var qrCode = new PngByteQRCode(qrCodeData);
        var qrCodeBytes = qrCode.GetGraphic(20);
        
        return Convert.ToBase64String(qrCodeBytes);
    }
}