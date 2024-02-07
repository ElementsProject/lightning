# A grpc model
import re

from msggen.model import Service
from msggen.gen.grpc.convert import GrpcConverterGenerator
from msggen.gen.grpc.util import method_name_overrides


class GrpcServerGenerator(GrpcConverterGenerator):
    def generate(self, service: Service) -> None:
        self.write(
            f"""\
        use crate::pb::node_server::Node;
        use crate::pb;
        use cln_rpc::{{Request, Response, ClnRpc}};
        use anyhow::Result;
        use std::path::{{Path, PathBuf}};
        use cln_rpc::model::requests;
        use log::{{debug, trace}};
        use tonic::{{Code, Status}};

        #[derive(Clone)]
        pub struct Server
        {{
            rpc_path: PathBuf,
        }}

        impl Server
        {{
            pub async fn new(path: &Path) -> Result<Self>
            {{
                Ok(Self {{
                    rpc_path: path.to_path_buf(),
                }})
            }}
        }}

        #[tonic::async_trait]
        impl Node for Server
        {{
        """
        )

        for method in service.methods:
            mname = method_name_overrides.get(method.name, method.name)
            # Tonic will convert to snake-case, so we have to do it here too
            name = re.sub(r"(?<!_)(?<!^)(?=[A-Z])", "_", mname).lower()
            name = name.replace("-", "")
            method.name = method.name.replace("-", "")
            pbname_request = self.to_camel_case(str(method.request.typename))
            pbname_response = self.to_camel_case(str(method.response.typename))
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
                numindent=0,
            )

        self.write(
            f"""\
        }}
        """,
            numindent=0,
        )
