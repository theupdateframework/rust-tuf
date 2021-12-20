use futures_executor::block_on;
use interop_tests::generate_repos;
use std::path::Path;

const KEYS_PATH: &str = "./keys.json";

fn main() {
    let keys_path = Path::new(KEYS_PATH);

    block_on(async {
        generate_repos(keys_path, Path::new("consistent-snapshot-true"), true)
            .await
            .unwrap();
        generate_repos(keys_path, Path::new("consistent-snapshot-false"), false)
            .await
            .unwrap();
    })
}
