use crate::codec::JsonCodec;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_util::codec::FramedWrite;
pub mod codec;
mod messages;
pub use anyhow::Error;
use std::marker::PhantomData;
use tokio::io::Stdin;
use tokio::io::{AsyncRead, AsyncWrite};

/// Builder for a new plugin.
struct Builder<S, I, O>
where
    S: Clone + Send,
    I: AsyncRead,
    O: Send + AsyncWrite,
{
    state: S,

    input: I,
    output: O,
}

impl<S, I, O> Builder<S, I, O>
where
    O: Send + AsyncWrite + 'static,
    S: Clone + Send + 'static,
    I: AsyncRead + Send + 'static,
{
    pub fn new(state: S, input: I, output: O) -> Self {
        Self {
            state,
            input,
            output,
        }
    }

    #[allow(unused_mut)]
    pub fn run(mut self) -> Plugin<S, I, O> {
        let plugin = Plugin {
            state: Arc::new(Mutex::new(self.state)),
            output: FramedWrite::new(self.output, JsonCodec::new()),
            input_type: PhantomData,
        };

        tokio::task::spawn(plugin.run(self.input));
        unimplemented!()
    }

    pub fn build(mut self) -> (Plugin<S, I, O>, I) {
        (
            Plugin {
                state: Arc::new(Mutex::new(self.state)),
                output: FramedWrite::new(self.output, JsonCodec::new()),
                input_type: PhantomData,
            },
            self.input,
        )
    }
}

struct Plugin<S, I, O>
where
    S: Clone + Send,
    I: AsyncRead,
    O: Send + AsyncWrite,
{
    //input: FramedRead<Stdin, JsonCodec>,
    output: FramedWrite<O, JsonCodec>,

    /// The state gets cloned for each request
    state: Arc<Mutex<S>>,
    input_type: PhantomData<I>,
}

impl<S, I, O> Plugin<S, I, O>
where
    S: Clone + Send,
    I: AsyncRead + Send,
    O: Send + AsyncWrite,
{
    /// Read incoming requests from `lightningd` and dispatch their handling.
    #[allow(unused_mut)]
    async fn run(mut self, input: I) -> Result<(), Error> {
        unimplemented!()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn init() {
        let builder = Builder::new((), tokio::io::stdin(), tokio::io::stdout());
        let plugin = builder.build();
    }
}
