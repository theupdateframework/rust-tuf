macro_rules! try_future {
    ($e:expr) => {
        match $e {
            Ok(value) => value,
            Err(err) => {
                return Box::new(::futures::future::err(err.into()));
            }
        }
    }
}

macro_rules! try_stream {
    ($e:expr) => {
        match $e {
            Ok(value) => value,
            Err(err) => {
                return Box::new(::futures::stream::once(Err(err.into()))); //::std::from::From::from(err))));
            }
        }
    }
}
