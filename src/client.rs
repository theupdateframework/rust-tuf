use repository::Repository;

use metadata::interchange::{RawData, DataInterchange};
use tuf::Tuf;

pub struct Client<'a, D, R, Local, Remote>
    where D: 'a + DataInterchange,
          R: 'a + RawData<D>,
          Local: 'a + Repository<D, R>,
          Remote: 'a + Repository<D, R>
{
    tuf: &'a mut Tuf<D, R>,
    local: &'a mut Local,
    remote: &'a mut Remote,
}

impl<'a, D, R, Local, Remote> Client<'a, D, R, Local, Remote>
    where D: 'a + DataInterchange,
          R: 'a + RawData<D>,
          Local: 'a + Repository<D, R>,
          Remote: 'a + Repository<D, R>
{
}
