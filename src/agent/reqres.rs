use libp2p::request_response;
use rasn::{AsnType, Decode, Encode};
use stamp_core::{dag::TransactionID, util::BinaryVec};

/// Describes a simple, recursive querying mechanism for grabbing transactions from peers.
#[derive(Debug, AsnType, Encode, Decode)]
#[rasn(choice)]
pub enum TransactionQuery {
    /// All conditions must match (AND)
    #[rasn(tag(explicit(0)))]
    And(Vec<TransactionQuery>),
    /// Matches all transactions
    #[rasn(tag(explicit(1)))]
    All,
    /// This condition cannot match (NOT).
    #[rasn(tag(explicit(2)))]
    Not(Box<TransactionQuery>),
    /// Any of the conditions can match (OR)
    #[rasn(tag(explicit(3)))]
    Or(Vec<TransactionQuery>),
    /// Query transactions by their `ExtV1.context` field
    #[rasn(tag(explicit(4)))]
    TransactionContext {
        #[rasn(tag(explicit(0)))]
        key: BinaryVec,
        #[rasn(tag(explicit(1)))]
        val: BinaryVec,
    },
    /// Grab a transaction by its ID
    #[rasn(tag(explicit(5)))]
    TransactionID(TransactionID),
    /// Grab a transaction by its `ExtV1.type` field
    #[rasn(tag(explicit(6)))]
    TransactionType(BinaryVec),
}

/// A request into this p2p node from another node. This is generally used to run remote
/// commands or request transactions and such.
#[derive(Debug, AsnType, Encode, Decode)]
#[rasn(choice)]
pub enum Request {
    /// Request that this relay node follow a topic
    #[rasn(tag(explicit(0)))]
    JoinTopic(String),
    /// Ask for some transactions
    #[rasn(tag(explicit(1)))]
    QueryTransactions(TransactionQuery),
}

/// A response object, sent for a matching [`Request`].
#[derive(Debug, AsnType, Encode, Decode)]
#[rasn(choice)]
pub enum Response {
    /// Provide some transactions
    #[rasn(tag(explicit(0)))]
    Transactions(Vec<u8>),
}

pub type ReqresBehavior<Req, Resp> =
    request_response::Behaviour<reqres_asn1_codec::Codec<Req, Resp>>;

mod reqres_asn1_codec {
    use async_trait::async_trait;
    use futures::prelude::*;
    use futures::{AsyncRead, AsyncWrite};
    use libp2p::StreamProtocol;
    use rasn::{Decode, Encode};
    use stamp_core::rasn;
    use std::{io, marker::PhantomData};
    use tracing::error;

    /// Max request size in bytes
    const REQUEST_SIZE_MAXIMUM: u64 = 1024 * 1024;
    /// Max response size in bytes
    const RESPONSE_SIZE_MAXIMUM: u64 = 10 * 1024 * 1024;

    pub struct Codec<Req, Resp> {
        phantom: PhantomData<(Req, Resp)>,
    }

    impl<Req, Resp> Default for Codec<Req, Resp> {
        fn default() -> Self {
            Codec {
                phantom: PhantomData,
            }
        }
    }

    impl<Req, Resp> Clone for Codec<Req, Resp> {
        fn clone(&self) -> Self {
            Self::default()
        }
    }

    #[async_trait]
    impl<Req, Resp> libp2p::request_response::Codec for Codec<Req, Resp>
    where
        Req: Send + Encode + Decode,
        Resp: Send + Encode + Decode,
    {
        type Protocol = StreamProtocol;
        type Request = Req;
        type Response = Resp;

        async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Req>
        where
            T: AsyncRead + Unpin + Send,
        {
            let mut vec = Vec::new();
            io.take(REQUEST_SIZE_MAXIMUM).read_to_end(&mut vec).await?;
            let dec = rasn::der::decode(vec.as_slice()).map_err(|e| {
                error!("reqres: req: decode: {:?}", e);
                std::io::ErrorKind::Other
            })?;
            Ok(dec)
        }

        async fn read_response<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Resp>
        where
            T: AsyncRead + Unpin + Send,
        {
            let mut vec = Vec::new();
            io.take(RESPONSE_SIZE_MAXIMUM).read_to_end(&mut vec).await?;
            let dec = rasn::der::decode(vec.as_slice()).map_err(|e| {
                error!("reqres: res: decode: {:?}", e);
                std::io::ErrorKind::Other
            })?;
            Ok(dec)
        }

        async fn write_request<T>(
            &mut self,
            _: &Self::Protocol,
            io: &mut T,
            req: Self::Request,
        ) -> io::Result<()>
        where
            T: AsyncWrite + Unpin + Send,
        {
            let data = rasn::der::encode(&req).map_err(|e| {
                error!("reqres: req: encode: {:?}", e);
                std::io::ErrorKind::Other
            })?;
            io.write_all(data.as_ref()).await?;
            Ok(())
        }

        async fn write_response<T>(
            &mut self,
            _: &Self::Protocol,
            io: &mut T,
            resp: Self::Response,
        ) -> io::Result<()>
        where
            T: AsyncWrite + Unpin + Send,
        {
            let data = rasn::der::encode(&resp).map_err(|e| {
                error!("reqres: res: encode: {:?}", e);
                std::io::ErrorKind::Other
            })?;
            io.write_all(data.as_ref()).await?;
            Ok(())
        }
    }
}
