use hyper::{Url, Client};
use hyper::client::response::Response;
use hyper::header::{Headers, UserAgent};
use std::collections::HashMap;
use std::fs::{self, File, DirBuilder};
use std::io::Read;
use std::marker::PhantomData;
use std::path::PathBuf;

use Result;
use error::Error;
use metadata::{SignedMetadata, MetadataVersion, RootMetadata, Unverified, Verified};
use interchange::DataInterchange;

pub trait Repository<D>
where
    D: DataInterchange,
{
    fn initialize(&mut self) -> Result<()>;
    fn store_root(
        &mut self,
        root: &SignedMetadata<D, RootMetadata, Verified>,
        version: &MetadataVersion,
    ) -> Result<()>;
    fn fetch_root(
        &mut self,
        version: &MetadataVersion,
        max_size: &Option<usize>,
    ) -> Result<SignedMetadata<D, RootMetadata, Unverified>>;

    fn safe_read<Re: Read>(read: &mut Re, max_size: &Option<usize>) -> Result<Vec<u8>> {
        match max_size {
            &Some(max_size) => {
                let mut buf = vec![0; max_size];
                read.read_exact(&mut buf)?;
                Ok(buf)
            }
            &None => {
                let mut buf = Vec::new();
                let _ = read.read_to_end(&mut buf)?;
                Ok(buf)
            }
        }
    }
}

pub struct FileSystemRepository<D>
where
    D: DataInterchange,
{
    local_path: PathBuf,
    _interchange: PhantomData<D>,
}

impl<D> FileSystemRepository<D>
where
    D: DataInterchange,
{
    pub fn new(local_path: PathBuf) -> Self {
        FileSystemRepository {
            local_path: local_path,
            _interchange: PhantomData,
        }
    }
}

impl<D> Repository<D> for FileSystemRepository<D>
where
    D: DataInterchange,
{
    fn initialize(&mut self) -> Result<()> {
        for p in &["metadata", "targets"] {
            DirBuilder::new().recursive(true).create(
                self.local_path.join(p),
            )?
        }

        Ok(())
    }

    fn store_root(
        &mut self,
        root: &SignedMetadata<D, RootMetadata, Verified>,
        version: &MetadataVersion,
    ) -> Result<()> {
        let root_version = format!("{}root{}", version.prefix(), D::suffix());
        let path = self.local_path.join("metadata").join(&root_version);

        if path.exists() {
            debug!("Root path exists. Deleting: {}", root_version);
            fs::remove_file(&path)?
        }

        let mut file = File::create(&path)?;
        D::to_writer(&mut file, root)?;

        Ok(())
    }

    fn fetch_root(
        &mut self,
        version: &MetadataVersion,
        max_size: &Option<usize>,
    ) -> Result<SignedMetadata<D, RootMetadata, Unverified>> {
        let root_version = format!("{}root{}", version.prefix(), D::suffix());
        let path = self.local_path.join("metadata").join(&root_version);
        let mut file = File::open(&path)?;
        let buf = Self::safe_read(&mut file, max_size)?;
        Ok(D::from_reader(&*buf)?)
    }
}

pub struct HttpRepository<D>
where
    D: DataInterchange,
{
    url: Url,
    client: Client,
    user_agent: String,
    _interchange: PhantomData<D>,
}

impl<D> HttpRepository<D>
where
    D: DataInterchange,
{
    pub fn new(url: Url, client: Client, user_agent_prefix: Option<String>) -> Self {
        let user_agent = match user_agent_prefix {
            Some(ua) => format!("{} (rust-tuf/{})", ua, env!("CARGO_PKG_VERSION")),
            None => format!("rust-tuf/{}", env!("CARGO_PKG_VERSION")),
        };

        HttpRepository {
            url: url,
            client: client,
            user_agent: user_agent,
            _interchange: PhantomData,
        }
    }

    pub fn get(&self, path: &str) -> Result<Response> {
        let mut headers = Headers::new();
        headers.set(UserAgent(self.user_agent.clone()));

        let req = self.client.get(self.url.join(path)?).headers(headers);
        Ok(req.send()?)
    }
}

impl<D> Repository<D> for HttpRepository<D>
where
    D: DataInterchange,
{
    fn initialize(&mut self) -> Result<()> {
        Ok(())
    }

    fn store_root(
        &mut self,
        _: &SignedMetadata<D, RootMetadata, Verified>,
        _: &MetadataVersion,
    ) -> Result<()> {
        Err(Error::Generic(
            "Http repo store root not implemented".to_string(),
        ))
    }

    fn fetch_root(
        &mut self,
        version: &MetadataVersion,
        max_size: &Option<usize>,
    ) -> Result<SignedMetadata<D, RootMetadata, Unverified>> {
        let root_version = format!("{}root{}", version.prefix(), D::suffix());
        let mut resp = self.get(&root_version)?;
        let buf = Self::safe_read(&mut resp, max_size)?;
        Ok(D::from_reader(&*buf)?)
    }
}

pub struct EphemeralRepository<D>
where
    D: DataInterchange,
{
    metadata: HashMap<String, Vec<u8>>,
    _interchange: PhantomData<D>,
}

impl<D> EphemeralRepository<D>
where
    D: DataInterchange,
{
    pub fn new() -> Self {
        EphemeralRepository {
            metadata: HashMap::new(),
            _interchange: PhantomData,
        }
    }
}

impl<D> Repository<D> for EphemeralRepository<D>
where
    D: DataInterchange,
{
    fn initialize(&mut self) -> Result<()> {
        Ok(())
    }

    fn store_root(
        &mut self,
        root: &SignedMetadata<D, RootMetadata, Verified>,
        version: &MetadataVersion,
    ) -> Result<()> {
        let root_version = format!("{}root{}", version.prefix(), D::suffix());
        let mut buf = Vec::new();
        D::to_writer(&mut buf, root)?;
        let _ = self.metadata.insert(root_version, buf);
        Ok(())
    }

    fn fetch_root(
        &mut self,
        version: &MetadataVersion,
        max_size: &Option<usize>,
    ) -> Result<SignedMetadata<D, RootMetadata, Unverified>> {
        let root_version = format!("{}root{}", version.prefix(), D::suffix());
        match self.metadata.get(&root_version) {
            Some(bytes) => D::from_reader(&**bytes),
            None => Err(Error::NotFound),
        }
    }
}
