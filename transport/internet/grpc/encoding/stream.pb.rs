// Handwritten prost declarations for the exact pinned encoding/stream.proto.
// No protoc/build script or generated external dependency is required.
#[derive(Clone, PartialEq, prost::Message)]
pub struct Hunk {
    #[prost(bytes = "bytes", tag = "1")]
    pub data: bytes::Bytes,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct MultiHunk {
    #[prost(bytes = "bytes", repeated, tag = "1")]
    pub data: Vec<bytes::Bytes>,
}
