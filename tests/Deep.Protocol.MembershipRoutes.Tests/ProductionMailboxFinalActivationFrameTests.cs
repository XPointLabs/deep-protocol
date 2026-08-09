using System.Buffers.Binary;
using Deep.Protocol.DeepExtension.MailboxAuthority;
using Deep.Protocol.DeepExtension.MailboxTopology;
using Xunit;

namespace Deep.Protocol.MembershipRoutes.Tests;

public sealed class ProductionMailboxFinalActivationFrameTests
{
    [Fact]
    public void Pmfa1_OuterValidLateEightMiBMalformedPmtRejectsWithoutFullClone()
    {
        var lengths = new[] { 1, ProductionMailboxRevocationSnapshotConstants.FixedArtifactBytesWithoutSerials,
            ProductionMailboxTopologyConstants.MaximumTopologyArtifactBytes, 408, 408,
            ProductionMailboxSelectionSuccessorV2Constants.FixedCoreLength +
                ProductionMailboxSelectionSuccessorV2Constants.SignatureBytes + 3,
            304, 408, 0, 448 };
        var aggregate = lengths.Sum();
        var frame = new byte[48 + aggregate];
        "PMFA"u8.CopyTo(frame); frame[4] = 1; frame[5] = 1; frame[6] = 1;
        for (var i = 0; i < 10; i++)
            BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(8 + i * 4, 4), (uint)lengths[i]);
        var pmr = 48 + lengths[0];
        "PMR1"u8.CopyTo(frame.AsSpan(pmr)); frame[pmr + 4] = 1;
        var pmt = pmr + lengths[1];
        "PMT1"u8.CopyTo(frame.AsSpan(pmt)); frame[pmt + 4] = 1;
        var before = GC.GetAllocatedBytesForCurrentThread();
        Assert.Throws<FormatException>(() =>
            ProductionMailboxOwnerControlTransportCodec.DecodeFinalActivation(frame));
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        Assert.True(allocated < 128 * 1024, $"Unexpected reject-path allocation: {allocated} bytes.");
    }

    [Fact]
    public void Pmfa1_RejectsOwnerDelegatedShapeMixBeforeNestedDecode()
    {
        var frame = new byte[48]; "PMFA"u8.CopyTo(frame); frame[4] = 1; frame[5] = 1; frame[6] = 1;
        BinaryPrimitives.WriteUInt32BigEndian(frame.AsSpan(40, 4), 320);
        Assert.Throws<FormatException>(() =>
            ProductionMailboxOwnerControlTransportCodec.DecodeFinalActivation(frame));
    }

    [Fact]
    public async Task StreamedPmfa_OneByteChunksRejectHeaderBeforeBodyRent()
    {
        var header = new byte[48]; "PMFA"u8.CopyTo(header); header[4] = 1; header[5] = 1; header[6] = 1;
        var stream = new OneByteStream(header);
        await Assert.ThrowsAsync<FormatException>(async () =>
            await ProductionMailboxOwnerControlTransportCodec.ReadFinalActivationAsync(stream, 48));
        Assert.Equal(48, stream.BytesRead);
    }

    [Fact]
    public void HeaderFuzzNeverEscapesBoundedProtocolExceptions()
    {
        var random = new Random(17);
        for (var i = 0; i < 256; i++)
        {
            var bytes = new byte[random.Next(0, 96)]; random.NextBytes(bytes);
            var exception = Record.Exception(() =>
                ProductionMailboxOwnerControlTransportCodec.DecodeFinalActivation(bytes));
            Assert.IsType<FormatException>(exception);
        }
    }

    private sealed class OneByteStream(byte[] bytes) : MemoryStream(bytes, writable: false)
    {
        internal int BytesRead { get; private set; }
        public override ValueTask<int> ReadAsync(Memory<byte> buffer,
            CancellationToken cancellationToken = default)
        {
            var limited = buffer[..Math.Min(1, buffer.Length)];
            return ReadOneAsync(limited, cancellationToken);
        }
        private async ValueTask<int> ReadOneAsync(Memory<byte> buffer, CancellationToken cancellationToken)
        {
            var read = await base.ReadAsync(buffer, cancellationToken); BytesRead += read; return read;
        }
    }
}
