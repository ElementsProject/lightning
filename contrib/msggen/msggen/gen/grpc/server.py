# A grpc model
import re
import logging
from typing import TextIO, Optional
from msggen.model import Service
from msggen.gen.generator import IGenerator
from msggen.gen.grpc.util import (
    method_name_overrides,
    camel_to_snake,
    snake_to_camel,
    notification_typename_overrides,
)
from textwrap import indent, dedent


class GrpcServerGenerator(IGenerator):
    def __init__(self, dest: TextIO):
        self.dest = dest
        self.logger = logging.getLogger(__name__)

    def write(self, text: str, numindent: Optional[int] = None):
        if numindent is None:
            self.dest.write(text)
        else:
            text = dedent(text)
            text = indent(text, "    " * numindent)
            self.dest.write(text)

    def generate(self, service: Service) -> None:
        self.write(
            f"""\
        use crate::pb::node_server::Node;
        use crate::pb;
        use cln_rpc::{{Request, Response, ClnRpc}};
        use cln_rpc::notifications::Notification;
        use anyhow::Result;
        use std::path::{{Path, PathBuf}};
        use std::pin::Pin;
        use std::task::{{Context, Poll}};
        use cln_rpc::model::requests;
        use log::{{debug, trace}};
        use tonic::{{Code, Status}};
        use tokio::sync::broadcast;
        use tokio_stream::wrappers::errors::BroadcastStreamRecvError;
        use tokio_stream::wrappers::BroadcastStream;


        #[derive(Clone)]
        pub struct Server
        {{
            rpc_path: PathBuf,
            events : broadcast::Sender<Notification>
        }}

        impl Server
        {{
            pub async fn new(
                path: &Path,
                events : broadcast::Sender<Notification>
            ) -> Result<Self>
            {{
                Ok(Self {{
                    rpc_path: path.to_path_buf(),
                    events : events
                }})
            }}
        }}

        pub struct NotificationStream<T> {{
            inner : Pin<Box<BroadcastStream<Notification>>>,
            fn_filter_map : fn(Notification) -> Option<T>
        }}

        impl<T : 'static + Send + Clone> tokio_stream::Stream for NotificationStream<T> {{

            type Item = Result<T, tonic::Status>;

            fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {{
                while let Poll::Ready(result) = self.inner.as_mut().poll_next(cx) {{
                    // None is used here to signal that we have reached the end of stream
                    // If inner ends the stream by returning None we do the same
                    if result.is_none() {{
                        return Poll::Ready(None)
                    }}
                    let result: Result<cln_rpc::Notification, BroadcastStreamRecvError> = result.unwrap();

                    match result {{
                        Err(BroadcastStreamRecvError::Lagged(lag)) => {{
                            // In this error case we've missed some notifications
                            // We log the error to core lightning and forward
                            // this information to the client
                            log::warn!("Due to lag the grpc-server skipped {{}} notifications", lag);
                            return Poll::Ready(Some(Err(
                                Status::data_loss(
                                    format!("Skipped up to {{}} notifications", lag)))))
                        }}
                        Ok(notification) => {{
                            let filtered = (self.fn_filter_map)(notification);
                            match filtered {{
                                Some(n) => return Poll::Ready(Some(Ok(n))),
                                None => {{
                                    // We ignore the message if it isn't a match.
                                    // e.g: A `ChannelOpenedStream` will ignore `CustomMsgNotifications`
                                }}
                            }}
                        }}
                    }}
                }}
                Poll::Pending
            }}
        }}

        #[tonic::async_trait]
        impl Node for Server
        {{
        """,
            numindent=0,
        )

        for method in service.methods:
            mname = method_name_overrides.get(method.name, method.name)
            # Tonic will convert to snake-case, so we have to do it here too
            name = re.sub(r"(?<!_)(?<!^)(?=[A-Z])", "_", mname).lower()
            name = name.replace("-", "")
            method.name = method.name.replace("-", "")
            pbname_request = snake_to_camel(str(method.request.typename))
            pbname_response = snake_to_camel(str(method.response.typename))
            self.write(
                f"""\
            async fn {name}(
                &self,
                request: tonic::Request<pb::{pbname_request}>,
            ) -> Result<tonic::Response<pb::{pbname_response}>, tonic::Status> {{
                let req = request.into_inner();
                let req: requests::{method.request.typename} = req.into();
                debug!("Client asked for {name}");
                trace!("{name} request: {{:?}}", req);
                let mut rpc = ClnRpc::new(&self.rpc_path)
                    .await
                    .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
                let result = rpc.call(Request::{method.name}(req))
                    .await
                    .map_err(|e| Status::new(
                       Code::Unknown,
                       format!("Error calling method {method.name}: {{:?}}", e)))?;
                match result {{
                    Response::{method.name}(r) => {{
                       trace!("{name} response: {{:?}}", r);
                       Ok(tonic::Response::new(r.into()))
                    }},
                    r => Err(Status::new(
                        Code::Internal,
                        format!(
                            "Unexpected result {{:?}} to method call {method.name}",
                            r
                        )
                    )),
                }}

            }}\n\n""",
                numindent=1,
            )

        for notification in service.notifications:
            typename = str(notification.typename)
            snake_name = camel_to_snake(typename)
            response_name = notification_typename_overrides(
                str(notification.response.typename)
            )
            stream_request = f"Stream{typename}Request"
            stream_name = f"Subscribe{notification.typename}Stream"
            self.write(
                f"""

            type Subscribe{typename}Stream = NotificationStream<pb::{response_name}>;

            async fn subscribe_{snake_name}(
                &self,
                _request : tonic::Request<pb::{stream_request}>
            ) -> Result<tonic::Response<Self::{stream_name}>, tonic::Status> {{
                let receiver = self.events.subscribe();
                let stream = BroadcastStream::new(receiver);
                let boxed = Box::pin(stream);

                let result = NotificationStream {{
                    inner : boxed,
                    fn_filter_map : |x| {{
                        match x {{
                            Notification::{typename}(x) => {{
                                Some(x.into())
                            }}
                            _ => None
                        }}
                    }}
                }};
                Ok(tonic::Response::new(result))
            }}
            """,
                numindent=1,
            )

        self.write("""}""", numindent=0)
