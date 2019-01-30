// <auto-generated>
//     Generated by the protocol buffer compiler.  DO NOT EDIT!
//     source: peer/query.proto
// </auto-generated>
#pragma warning disable 1591, 0612, 3021
#region Designer generated code

using pb = global::Google.Protobuf;
using pbc = global::Google.Protobuf.Collections;
using pbr = global::Google.Protobuf.Reflection;
using scg = global::System.Collections.Generic;
namespace Protos {

  /// <summary>Holder for reflection information generated from peer/query.proto</summary>
  public static partial class QueryReflection {

    #region Descriptor
    /// <summary>File descriptor for peer/query.proto</summary>
    public static pbr::FileDescriptor Descriptor {
      get { return descriptor; }
    }
    private static pbr::FileDescriptor descriptor;

    static QueryReflection() {
      byte[] descriptorData = global::System.Convert.FromBase64String(
          string.Concat(
            "ChBwZWVyL3F1ZXJ5LnByb3RvEgZwcm90b3MiQwoWQ2hhaW5jb2RlUXVlcnlS",
            "ZXNwb25zZRIpCgpjaGFpbmNvZGVzGAEgAygLMhUucHJvdG9zLkNoYWluY29k",
            "ZUluZm8icwoNQ2hhaW5jb2RlSW5mbxIMCgRuYW1lGAEgASgJEg8KB3ZlcnNp",
            "b24YAiABKAkSDAoEcGF0aBgDIAEoCRINCgVpbnB1dBgEIAEoCRIMCgRlc2Nj",
            "GAUgASgJEgwKBHZzY2MYBiABKAkSCgoCaWQYByABKAwiPQoUQ2hhbm5lbFF1",
            "ZXJ5UmVzcG9uc2USJQoIY2hhbm5lbHMYASADKAsyEy5wcm90b3MuQ2hhbm5l",
            "bEluZm8iIQoLQ2hhbm5lbEluZm8SEgoKY2hhbm5lbF9pZBgBIAEoCUJPCiJv",
            "cmcuaHlwZXJsZWRnZXIuZmFicmljLnByb3Rvcy5wZWVyWilnaXRodWIuY29t",
            "L2h5cGVybGVkZ2VyL2ZhYnJpYy9wcm90b3MvcGVlcmIGcHJvdG8z"));
      descriptor = pbr::FileDescriptor.FromGeneratedCode(descriptorData,
          new pbr::FileDescriptor[] { },
          new pbr::GeneratedClrTypeInfo(null, new pbr::GeneratedClrTypeInfo[] {
            new pbr::GeneratedClrTypeInfo(typeof(global::Protos.ChaincodeQueryResponse), global::Protos.ChaincodeQueryResponse.Parser, new[]{ "Chaincodes" }, null, null, null),
            new pbr::GeneratedClrTypeInfo(typeof(global::Protos.ChaincodeInfo), global::Protos.ChaincodeInfo.Parser, new[]{ "Name", "Version", "Path", "Input", "Escc", "Vscc", "Id" }, null, null, null),
            new pbr::GeneratedClrTypeInfo(typeof(global::Protos.ChannelQueryResponse), global::Protos.ChannelQueryResponse.Parser, new[]{ "Channels" }, null, null, null),
            new pbr::GeneratedClrTypeInfo(typeof(global::Protos.ChannelInfo), global::Protos.ChannelInfo.Parser, new[]{ "ChannelId" }, null, null, null)
          }));
    }
    #endregion

  }
  #region Messages
  /// <summary>
  /// ChaincodeQueryResponse returns information about each chaincode that pertains
  /// to a query in lscc.go, such as GetChaincodes (returns all chaincodes
  /// instantiated on a channel), and GetInstalledChaincodes (returns all chaincodes
  /// installed on a peer)
  /// </summary>
  public sealed partial class ChaincodeQueryResponse : pb::IMessage<ChaincodeQueryResponse> {
    private static readonly pb::MessageParser<ChaincodeQueryResponse> _parser = new pb::MessageParser<ChaincodeQueryResponse>(() => new ChaincodeQueryResponse());
    private pb::UnknownFieldSet _unknownFields;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public static pb::MessageParser<ChaincodeQueryResponse> Parser { get { return _parser; } }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public static pbr::MessageDescriptor Descriptor {
      get { return global::Protos.QueryReflection.Descriptor.MessageTypes[0]; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    pbr::MessageDescriptor pb::IMessage.Descriptor {
      get { return Descriptor; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public ChaincodeQueryResponse() {
      OnConstruction();
    }

    partial void OnConstruction();

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public ChaincodeQueryResponse(ChaincodeQueryResponse other) : this() {
      chaincodes_ = other.chaincodes_.Clone();
      _unknownFields = pb::UnknownFieldSet.Clone(other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public ChaincodeQueryResponse Clone() {
      return new ChaincodeQueryResponse(this);
    }

    /// <summary>Field number for the "chaincodes" field.</summary>
    public const int ChaincodesFieldNumber = 1;
    private static readonly pb::FieldCodec<global::Protos.ChaincodeInfo> _repeated_chaincodes_codec
        = pb::FieldCodec.ForMessage(10, global::Protos.ChaincodeInfo.Parser);
    private readonly pbc::RepeatedField<global::Protos.ChaincodeInfo> chaincodes_ = new pbc::RepeatedField<global::Protos.ChaincodeInfo>();
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public pbc::RepeatedField<global::Protos.ChaincodeInfo> Chaincodes {
      get { return chaincodes_; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public override bool Equals(object other) {
      return Equals(other as ChaincodeQueryResponse);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public bool Equals(ChaincodeQueryResponse other) {
      if (ReferenceEquals(other, null)) {
        return false;
      }
      if (ReferenceEquals(other, this)) {
        return true;
      }
      if(!chaincodes_.Equals(other.chaincodes_)) return false;
      return Equals(_unknownFields, other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public override int GetHashCode() {
      int hash = 1;
      hash ^= chaincodes_.GetHashCode();
      if (_unknownFields != null) {
        hash ^= _unknownFields.GetHashCode();
      }
      return hash;
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public override string ToString() {
      return pb::JsonFormatter.ToDiagnosticString(this);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public void WriteTo(pb::CodedOutputStream output) {
      chaincodes_.WriteTo(output, _repeated_chaincodes_codec);
      if (_unknownFields != null) {
        _unknownFields.WriteTo(output);
      }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public int CalculateSize() {
      int size = 0;
      size += chaincodes_.CalculateSize(_repeated_chaincodes_codec);
      if (_unknownFields != null) {
        size += _unknownFields.CalculateSize();
      }
      return size;
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public void MergeFrom(ChaincodeQueryResponse other) {
      if (other == null) {
        return;
      }
      chaincodes_.Add(other.chaincodes_);
      _unknownFields = pb::UnknownFieldSet.MergeFrom(_unknownFields, other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public void MergeFrom(pb::CodedInputStream input) {
      uint tag;
      while ((tag = input.ReadTag()) != 0) {
        switch(tag) {
          default:
            _unknownFields = pb::UnknownFieldSet.MergeFieldFrom(_unknownFields, input);
            break;
          case 10: {
            chaincodes_.AddEntriesFrom(input, _repeated_chaincodes_codec);
            break;
          }
        }
      }
    }

  }

  /// <summary>
  /// ChaincodeInfo contains general information about an installed/instantiated
  /// chaincode
  /// </summary>
  public sealed partial class ChaincodeInfo : pb::IMessage<ChaincodeInfo> {
    private static readonly pb::MessageParser<ChaincodeInfo> _parser = new pb::MessageParser<ChaincodeInfo>(() => new ChaincodeInfo());
    private pb::UnknownFieldSet _unknownFields;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public static pb::MessageParser<ChaincodeInfo> Parser { get { return _parser; } }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public static pbr::MessageDescriptor Descriptor {
      get { return global::Protos.QueryReflection.Descriptor.MessageTypes[1]; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    pbr::MessageDescriptor pb::IMessage.Descriptor {
      get { return Descriptor; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public ChaincodeInfo() {
      OnConstruction();
    }

    partial void OnConstruction();

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public ChaincodeInfo(ChaincodeInfo other) : this() {
      name_ = other.name_;
      version_ = other.version_;
      path_ = other.path_;
      input_ = other.input_;
      escc_ = other.escc_;
      vscc_ = other.vscc_;
      id_ = other.id_;
      _unknownFields = pb::UnknownFieldSet.Clone(other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public ChaincodeInfo Clone() {
      return new ChaincodeInfo(this);
    }

    /// <summary>Field number for the "name" field.</summary>
    public const int NameFieldNumber = 1;
    private string name_ = "";
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public string Name {
      get { return name_; }
      set {
        name_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    /// <summary>Field number for the "version" field.</summary>
    public const int VersionFieldNumber = 2;
    private string version_ = "";
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public string Version {
      get { return version_; }
      set {
        version_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    /// <summary>Field number for the "path" field.</summary>
    public const int PathFieldNumber = 3;
    private string path_ = "";
    /// <summary>
    /// the path as specified by the install/instantiate transaction
    /// </summary>
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public string Path {
      get { return path_; }
      set {
        path_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    /// <summary>Field number for the "input" field.</summary>
    public const int InputFieldNumber = 4;
    private string input_ = "";
    /// <summary>
    /// the chaincode function upon instantiation and its arguments. This will be
    /// blank if the query is returning information about installed chaincodes.
    /// </summary>
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public string Input {
      get { return input_; }
      set {
        input_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    /// <summary>Field number for the "escc" field.</summary>
    public const int EsccFieldNumber = 5;
    private string escc_ = "";
    /// <summary>
    /// the name of the ESCC for this chaincode. This will be
    /// blank if the query is returning information about installed chaincodes.
    /// </summary>
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public string Escc {
      get { return escc_; }
      set {
        escc_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    /// <summary>Field number for the "vscc" field.</summary>
    public const int VsccFieldNumber = 6;
    private string vscc_ = "";
    /// <summary>
    /// the name of the VSCC for this chaincode. This will be
    /// blank if the query is returning information about installed chaincodes.
    /// </summary>
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public string Vscc {
      get { return vscc_; }
      set {
        vscc_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    /// <summary>Field number for the "id" field.</summary>
    public const int IdFieldNumber = 7;
    private pb::ByteString id_ = pb::ByteString.Empty;
    /// <summary>
    /// the chaincode unique id.
    /// computed as: H(
    ///                H(name || version) ||
    ///                H(CodePackage)
    ///              )
    /// </summary>
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public pb::ByteString Id {
      get { return id_; }
      set {
        id_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public override bool Equals(object other) {
      return Equals(other as ChaincodeInfo);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public bool Equals(ChaincodeInfo other) {
      if (ReferenceEquals(other, null)) {
        return false;
      }
      if (ReferenceEquals(other, this)) {
        return true;
      }
      if (Name != other.Name) return false;
      if (Version != other.Version) return false;
      if (Path != other.Path) return false;
      if (Input != other.Input) return false;
      if (Escc != other.Escc) return false;
      if (Vscc != other.Vscc) return false;
      if (Id != other.Id) return false;
      return Equals(_unknownFields, other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public override int GetHashCode() {
      int hash = 1;
      if (Name.Length != 0) hash ^= Name.GetHashCode();
      if (Version.Length != 0) hash ^= Version.GetHashCode();
      if (Path.Length != 0) hash ^= Path.GetHashCode();
      if (Input.Length != 0) hash ^= Input.GetHashCode();
      if (Escc.Length != 0) hash ^= Escc.GetHashCode();
      if (Vscc.Length != 0) hash ^= Vscc.GetHashCode();
      if (Id.Length != 0) hash ^= Id.GetHashCode();
      if (_unknownFields != null) {
        hash ^= _unknownFields.GetHashCode();
      }
      return hash;
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public override string ToString() {
      return pb::JsonFormatter.ToDiagnosticString(this);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public void WriteTo(pb::CodedOutputStream output) {
      if (Name.Length != 0) {
        output.WriteRawTag(10);
        output.WriteString(Name);
      }
      if (Version.Length != 0) {
        output.WriteRawTag(18);
        output.WriteString(Version);
      }
      if (Path.Length != 0) {
        output.WriteRawTag(26);
        output.WriteString(Path);
      }
      if (Input.Length != 0) {
        output.WriteRawTag(34);
        output.WriteString(Input);
      }
      if (Escc.Length != 0) {
        output.WriteRawTag(42);
        output.WriteString(Escc);
      }
      if (Vscc.Length != 0) {
        output.WriteRawTag(50);
        output.WriteString(Vscc);
      }
      if (Id.Length != 0) {
        output.WriteRawTag(58);
        output.WriteBytes(Id);
      }
      if (_unknownFields != null) {
        _unknownFields.WriteTo(output);
      }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public int CalculateSize() {
      int size = 0;
      if (Name.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeStringSize(Name);
      }
      if (Version.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeStringSize(Version);
      }
      if (Path.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeStringSize(Path);
      }
      if (Input.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeStringSize(Input);
      }
      if (Escc.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeStringSize(Escc);
      }
      if (Vscc.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeStringSize(Vscc);
      }
      if (Id.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeBytesSize(Id);
      }
      if (_unknownFields != null) {
        size += _unknownFields.CalculateSize();
      }
      return size;
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public void MergeFrom(ChaincodeInfo other) {
      if (other == null) {
        return;
      }
      if (other.Name.Length != 0) {
        Name = other.Name;
      }
      if (other.Version.Length != 0) {
        Version = other.Version;
      }
      if (other.Path.Length != 0) {
        Path = other.Path;
      }
      if (other.Input.Length != 0) {
        Input = other.Input;
      }
      if (other.Escc.Length != 0) {
        Escc = other.Escc;
      }
      if (other.Vscc.Length != 0) {
        Vscc = other.Vscc;
      }
      if (other.Id.Length != 0) {
        Id = other.Id;
      }
      _unknownFields = pb::UnknownFieldSet.MergeFrom(_unknownFields, other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public void MergeFrom(pb::CodedInputStream input) {
      uint tag;
      while ((tag = input.ReadTag()) != 0) {
        switch(tag) {
          default:
            _unknownFields = pb::UnknownFieldSet.MergeFieldFrom(_unknownFields, input);
            break;
          case 10: {
            Name = input.ReadString();
            break;
          }
          case 18: {
            Version = input.ReadString();
            break;
          }
          case 26: {
            Path = input.ReadString();
            break;
          }
          case 34: {
            Input = input.ReadString();
            break;
          }
          case 42: {
            Escc = input.ReadString();
            break;
          }
          case 50: {
            Vscc = input.ReadString();
            break;
          }
          case 58: {
            Id = input.ReadBytes();
            break;
          }
        }
      }
    }

  }

  /// <summary>
  /// ChannelQueryResponse returns information about each channel that pertains
  /// to a query in lscc.go, such as GetChannels (returns all channels for a
  /// given peer)
  /// </summary>
  public sealed partial class ChannelQueryResponse : pb::IMessage<ChannelQueryResponse> {
    private static readonly pb::MessageParser<ChannelQueryResponse> _parser = new pb::MessageParser<ChannelQueryResponse>(() => new ChannelQueryResponse());
    private pb::UnknownFieldSet _unknownFields;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public static pb::MessageParser<ChannelQueryResponse> Parser { get { return _parser; } }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public static pbr::MessageDescriptor Descriptor {
      get { return global::Protos.QueryReflection.Descriptor.MessageTypes[2]; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    pbr::MessageDescriptor pb::IMessage.Descriptor {
      get { return Descriptor; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public ChannelQueryResponse() {
      OnConstruction();
    }

    partial void OnConstruction();

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public ChannelQueryResponse(ChannelQueryResponse other) : this() {
      channels_ = other.channels_.Clone();
      _unknownFields = pb::UnknownFieldSet.Clone(other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public ChannelQueryResponse Clone() {
      return new ChannelQueryResponse(this);
    }

    /// <summary>Field number for the "channels" field.</summary>
    public const int ChannelsFieldNumber = 1;
    private static readonly pb::FieldCodec<global::Protos.ChannelInfo> _repeated_channels_codec
        = pb::FieldCodec.ForMessage(10, global::Protos.ChannelInfo.Parser);
    private readonly pbc::RepeatedField<global::Protos.ChannelInfo> channels_ = new pbc::RepeatedField<global::Protos.ChannelInfo>();
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public pbc::RepeatedField<global::Protos.ChannelInfo> Channels {
      get { return channels_; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public override bool Equals(object other) {
      return Equals(other as ChannelQueryResponse);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public bool Equals(ChannelQueryResponse other) {
      if (ReferenceEquals(other, null)) {
        return false;
      }
      if (ReferenceEquals(other, this)) {
        return true;
      }
      if(!channels_.Equals(other.channels_)) return false;
      return Equals(_unknownFields, other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public override int GetHashCode() {
      int hash = 1;
      hash ^= channels_.GetHashCode();
      if (_unknownFields != null) {
        hash ^= _unknownFields.GetHashCode();
      }
      return hash;
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public override string ToString() {
      return pb::JsonFormatter.ToDiagnosticString(this);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public void WriteTo(pb::CodedOutputStream output) {
      channels_.WriteTo(output, _repeated_channels_codec);
      if (_unknownFields != null) {
        _unknownFields.WriteTo(output);
      }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public int CalculateSize() {
      int size = 0;
      size += channels_.CalculateSize(_repeated_channels_codec);
      if (_unknownFields != null) {
        size += _unknownFields.CalculateSize();
      }
      return size;
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public void MergeFrom(ChannelQueryResponse other) {
      if (other == null) {
        return;
      }
      channels_.Add(other.channels_);
      _unknownFields = pb::UnknownFieldSet.MergeFrom(_unknownFields, other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public void MergeFrom(pb::CodedInputStream input) {
      uint tag;
      while ((tag = input.ReadTag()) != 0) {
        switch(tag) {
          default:
            _unknownFields = pb::UnknownFieldSet.MergeFieldFrom(_unknownFields, input);
            break;
          case 10: {
            channels_.AddEntriesFrom(input, _repeated_channels_codec);
            break;
          }
        }
      }
    }

  }

  /// <summary>
  /// ChannelInfo contains general information about channels
  /// </summary>
  public sealed partial class ChannelInfo : pb::IMessage<ChannelInfo> {
    private static readonly pb::MessageParser<ChannelInfo> _parser = new pb::MessageParser<ChannelInfo>(() => new ChannelInfo());
    private pb::UnknownFieldSet _unknownFields;
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public static pb::MessageParser<ChannelInfo> Parser { get { return _parser; } }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public static pbr::MessageDescriptor Descriptor {
      get { return global::Protos.QueryReflection.Descriptor.MessageTypes[3]; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    pbr::MessageDescriptor pb::IMessage.Descriptor {
      get { return Descriptor; }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public ChannelInfo() {
      OnConstruction();
    }

    partial void OnConstruction();

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public ChannelInfo(ChannelInfo other) : this() {
      channelId_ = other.channelId_;
      _unknownFields = pb::UnknownFieldSet.Clone(other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public ChannelInfo Clone() {
      return new ChannelInfo(this);
    }

    /// <summary>Field number for the "channel_id" field.</summary>
    public const int ChannelIdFieldNumber = 1;
    private string channelId_ = "";
    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public string ChannelId {
      get { return channelId_; }
      set {
        channelId_ = pb::ProtoPreconditions.CheckNotNull(value, "value");
      }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public override bool Equals(object other) {
      return Equals(other as ChannelInfo);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public bool Equals(ChannelInfo other) {
      if (ReferenceEquals(other, null)) {
        return false;
      }
      if (ReferenceEquals(other, this)) {
        return true;
      }
      if (ChannelId != other.ChannelId) return false;
      return Equals(_unknownFields, other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public override int GetHashCode() {
      int hash = 1;
      if (ChannelId.Length != 0) hash ^= ChannelId.GetHashCode();
      if (_unknownFields != null) {
        hash ^= _unknownFields.GetHashCode();
      }
      return hash;
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public override string ToString() {
      return pb::JsonFormatter.ToDiagnosticString(this);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public void WriteTo(pb::CodedOutputStream output) {
      if (ChannelId.Length != 0) {
        output.WriteRawTag(10);
        output.WriteString(ChannelId);
      }
      if (_unknownFields != null) {
        _unknownFields.WriteTo(output);
      }
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public int CalculateSize() {
      int size = 0;
      if (ChannelId.Length != 0) {
        size += 1 + pb::CodedOutputStream.ComputeStringSize(ChannelId);
      }
      if (_unknownFields != null) {
        size += _unknownFields.CalculateSize();
      }
      return size;
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public void MergeFrom(ChannelInfo other) {
      if (other == null) {
        return;
      }
      if (other.ChannelId.Length != 0) {
        ChannelId = other.ChannelId;
      }
      _unknownFields = pb::UnknownFieldSet.MergeFrom(_unknownFields, other._unknownFields);
    }

    [global::System.Diagnostics.DebuggerNonUserCodeAttribute]
    public void MergeFrom(pb::CodedInputStream input) {
      uint tag;
      while ((tag = input.ReadTag()) != 0) {
        switch(tag) {
          default:
            _unknownFields = pb::UnknownFieldSet.MergeFieldFrom(_unknownFields, input);
            break;
          case 10: {
            ChannelId = input.ReadString();
            break;
          }
        }
      }
    }

  }

  #endregion

}

#endregion Designer generated code
