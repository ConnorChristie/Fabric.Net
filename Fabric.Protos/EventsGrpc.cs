// <auto-generated>
//     Generated by the protocol buffer compiler.  DO NOT EDIT!
//     source: peer/events.proto
// </auto-generated>
// Original file comments:
//
// Copyright IBM Corp. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//
#pragma warning disable 0414, 1591
#region Designer generated code

using grpc = global::Grpc.Core;

namespace Protos {
  public static partial class Deliver
  {
    static readonly string __ServiceName = "protos.Deliver";

    static readonly grpc::Marshaller<global::Common.Envelope> __Marshaller_common_Envelope = grpc::Marshallers.Create((arg) => global::Google.Protobuf.MessageExtensions.ToByteArray(arg), global::Common.Envelope.Parser.ParseFrom);
    static readonly grpc::Marshaller<global::Protos.DeliverResponse> __Marshaller_protos_DeliverResponse = grpc::Marshallers.Create((arg) => global::Google.Protobuf.MessageExtensions.ToByteArray(arg), global::Protos.DeliverResponse.Parser.ParseFrom);

    static readonly grpc::Method<global::Common.Envelope, global::Protos.DeliverResponse> __Method_Deliver = new grpc::Method<global::Common.Envelope, global::Protos.DeliverResponse>(
        grpc::MethodType.DuplexStreaming,
        __ServiceName,
        "Deliver",
        __Marshaller_common_Envelope,
        __Marshaller_protos_DeliverResponse);

    static readonly grpc::Method<global::Common.Envelope, global::Protos.DeliverResponse> __Method_DeliverFiltered = new grpc::Method<global::Common.Envelope, global::Protos.DeliverResponse>(
        grpc::MethodType.DuplexStreaming,
        __ServiceName,
        "DeliverFiltered",
        __Marshaller_common_Envelope,
        __Marshaller_protos_DeliverResponse);

    /// <summary>Service descriptor</summary>
    public static global::Google.Protobuf.Reflection.ServiceDescriptor Descriptor
    {
      get { return global::Protos.EventsReflection.Descriptor.Services[0]; }
    }

    /// <summary>Base class for server-side implementations of Deliver</summary>
    public abstract partial class DeliverBase
    {
      /// <summary>
      /// deliver first requires an Envelope of type ab.DELIVER_SEEK_INFO with
      /// Payload data as a marshaled orderer.SeekInfo message,
      /// then a stream of block replies is received
      /// </summary>
      /// <param name="requestStream">Used for reading requests from the client.</param>
      /// <param name="responseStream">Used for sending responses back to the client.</param>
      /// <param name="context">The context of the server-side call handler being invoked.</param>
      /// <returns>A task indicating completion of the handler.</returns>
      public virtual global::System.Threading.Tasks.Task Deliver(grpc::IAsyncStreamReader<global::Common.Envelope> requestStream, grpc::IServerStreamWriter<global::Protos.DeliverResponse> responseStream, grpc::ServerCallContext context)
      {
        throw new grpc::RpcException(new grpc::Status(grpc::StatusCode.Unimplemented, ""));
      }

      /// <summary>
      /// deliver first requires an Envelope of type ab.DELIVER_SEEK_INFO with
      /// Payload data as a marshaled orderer.SeekInfo message,
      /// then a stream of **filtered** block replies is received
      /// </summary>
      /// <param name="requestStream">Used for reading requests from the client.</param>
      /// <param name="responseStream">Used for sending responses back to the client.</param>
      /// <param name="context">The context of the server-side call handler being invoked.</param>
      /// <returns>A task indicating completion of the handler.</returns>
      public virtual global::System.Threading.Tasks.Task DeliverFiltered(grpc::IAsyncStreamReader<global::Common.Envelope> requestStream, grpc::IServerStreamWriter<global::Protos.DeliverResponse> responseStream, grpc::ServerCallContext context)
      {
        throw new grpc::RpcException(new grpc::Status(grpc::StatusCode.Unimplemented, ""));
      }

    }

    /// <summary>Client for Deliver</summary>
    public partial class DeliverClient : grpc::ClientBase<DeliverClient>
    {
      /// <summary>Creates a new client for Deliver</summary>
      /// <param name="channel">The channel to use to make remote calls.</param>
      public DeliverClient(grpc::Channel channel) : base(channel)
      {
      }
      /// <summary>Creates a new client for Deliver that uses a custom <c>CallInvoker</c>.</summary>
      /// <param name="callInvoker">The callInvoker to use to make remote calls.</param>
      public DeliverClient(grpc::CallInvoker callInvoker) : base(callInvoker)
      {
      }
      /// <summary>Protected parameterless constructor to allow creation of test doubles.</summary>
      protected DeliverClient() : base()
      {
      }
      /// <summary>Protected constructor to allow creation of configured clients.</summary>
      /// <param name="configuration">The client configuration.</param>
      protected DeliverClient(ClientBaseConfiguration configuration) : base(configuration)
      {
      }

      /// <summary>
      /// deliver first requires an Envelope of type ab.DELIVER_SEEK_INFO with
      /// Payload data as a marshaled orderer.SeekInfo message,
      /// then a stream of block replies is received
      /// </summary>
      /// <param name="headers">The initial metadata to send with the call. This parameter is optional.</param>
      /// <param name="deadline">An optional deadline for the call. The call will be cancelled if deadline is hit.</param>
      /// <param name="cancellationToken">An optional token for canceling the call.</param>
      /// <returns>The call object.</returns>
      public virtual grpc::AsyncDuplexStreamingCall<global::Common.Envelope, global::Protos.DeliverResponse> Deliver(grpc::Metadata headers = null, global::System.DateTime? deadline = null, global::System.Threading.CancellationToken cancellationToken = default(global::System.Threading.CancellationToken))
      {
        return Deliver(new grpc::CallOptions(headers, deadline, cancellationToken));
      }
      /// <summary>
      /// deliver first requires an Envelope of type ab.DELIVER_SEEK_INFO with
      /// Payload data as a marshaled orderer.SeekInfo message,
      /// then a stream of block replies is received
      /// </summary>
      /// <param name="options">The options for the call.</param>
      /// <returns>The call object.</returns>
      public virtual grpc::AsyncDuplexStreamingCall<global::Common.Envelope, global::Protos.DeliverResponse> Deliver(grpc::CallOptions options)
      {
        return CallInvoker.AsyncDuplexStreamingCall(__Method_Deliver, null, options);
      }
      /// <summary>
      /// deliver first requires an Envelope of type ab.DELIVER_SEEK_INFO with
      /// Payload data as a marshaled orderer.SeekInfo message,
      /// then a stream of **filtered** block replies is received
      /// </summary>
      /// <param name="headers">The initial metadata to send with the call. This parameter is optional.</param>
      /// <param name="deadline">An optional deadline for the call. The call will be cancelled if deadline is hit.</param>
      /// <param name="cancellationToken">An optional token for canceling the call.</param>
      /// <returns>The call object.</returns>
      public virtual grpc::AsyncDuplexStreamingCall<global::Common.Envelope, global::Protos.DeliverResponse> DeliverFiltered(grpc::Metadata headers = null, global::System.DateTime? deadline = null, global::System.Threading.CancellationToken cancellationToken = default(global::System.Threading.CancellationToken))
      {
        return DeliverFiltered(new grpc::CallOptions(headers, deadline, cancellationToken));
      }
      /// <summary>
      /// deliver first requires an Envelope of type ab.DELIVER_SEEK_INFO with
      /// Payload data as a marshaled orderer.SeekInfo message,
      /// then a stream of **filtered** block replies is received
      /// </summary>
      /// <param name="options">The options for the call.</param>
      /// <returns>The call object.</returns>
      public virtual grpc::AsyncDuplexStreamingCall<global::Common.Envelope, global::Protos.DeliverResponse> DeliverFiltered(grpc::CallOptions options)
      {
        return CallInvoker.AsyncDuplexStreamingCall(__Method_DeliverFiltered, null, options);
      }
      /// <summary>Creates a new instance of client from given <c>ClientBaseConfiguration</c>.</summary>
      protected override DeliverClient NewInstance(ClientBaseConfiguration configuration)
      {
        return new DeliverClient(configuration);
      }
    }

    /// <summary>Creates service definition that can be registered with a server</summary>
    /// <param name="serviceImpl">An object implementing the server-side handling logic.</param>
    public static grpc::ServerServiceDefinition BindService(DeliverBase serviceImpl)
    {
      return grpc::ServerServiceDefinition.CreateBuilder()
          .AddMethod(__Method_Deliver, serviceImpl.Deliver)
          .AddMethod(__Method_DeliverFiltered, serviceImpl.DeliverFiltered).Build();
    }

    /// <summary>Register service method implementations with a service binder. Useful when customizing the service binding logic.
    /// Note: this method is part of an experimental API that can change or be removed without any prior notice.</summary>
    /// <param name="serviceBinder">Service methods will be bound by calling <c>AddMethod</c> on this object.</param>
    /// <param name="serviceImpl">An object implementing the server-side handling logic.</param>
    public static void BindService(grpc::ServiceBinderBase serviceBinder, DeliverBase serviceImpl)
    {
      serviceBinder.AddMethod(__Method_Deliver, serviceImpl.Deliver);
      serviceBinder.AddMethod(__Method_DeliverFiltered, serviceImpl.DeliverFiltered);
    }

  }
}
#endregion
