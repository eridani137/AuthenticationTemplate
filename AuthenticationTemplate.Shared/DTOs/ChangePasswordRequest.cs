namespace AuthenticationTemplate.Shared.DTOs;


public record ChangePasswordRequest(string CurrentPassword, string NewPassword, string ConfirmNewPassword)
{
    public string CurrentPassword { get; set; } = CurrentPassword;
    public string NewPassword { get; set; } = NewPassword;
    public string ConfirmNewPassword { get; set; } = ConfirmNewPassword;
}