use tokio::fs::set_permissions;
use std::fs::Permissions;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

pub async fn change_permissions(path: String) -> String {
    #[cfg(unix)]
    {
        let perm = Permissions::from_mode(0o644);

        //SINK
        let _ = set_permissions(&path, perm).await;
    }

    path
}
