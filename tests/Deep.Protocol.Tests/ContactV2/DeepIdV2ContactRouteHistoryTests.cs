using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text.Json;
using Deep.Protocol.AccountDirectoryV1;
using Deep.Protocol.ApplicationCore;
using Deep.Protocol.ContactV1;
using Deep.Protocol.ContactV2;
using Deep.Protocol.Tests.ContactV1;

namespace Deep.Protocol.Tests.ContactV2;

/// <summary>Structural and exact-lineage tests only. Synthetic public records
/// do not assert signature verification, native custody, current routing or E2E.</summary>
public sealed class DeepIdV2ContactRouteHistoryTests
{
    [Theory]
    [InlineData(1, 1)]
    [InlineData(1, 3)]
    [InlineData(2, 0)]
    [InlineData(3, 1)]
    [InlineData(4, 0)]
    public void ClosedModesPreserveExactOriginalAtomsAndSeparateRetainedPayload(int mode, int count)
    {
        var exact = Page(mode, Enumerable.Repeat(Atom(false, false), count).ToArray());
        var original = exact.ToArray(); var package = Package(false);
        var payload = DeepIdV2ContactRouteHistoryCodec.Decode(exact, package.Authorization.NetworkId.Span);
        Assert.Equal((DeepIdV2ContactRouteHistoryMode)mode, payload.Mode); Assert.Equal(count, payload.Atoms.Count);
        exact.AsSpan().Clear(); Assert.Equal(original, payload.CanonicalBytes.ToArray());
        var record = Event(payload);
        var decoded = ApplicationCoreCodec.DecodeDmc2(record.CanonicalBytes.Span);
        Assert.IsType<ContactRouteHistoryDmc2Payload>(decoded.ParsedPayload);
        Assert.False(decoded.ParsedPayload is ContactRouteUpdateDmc2Payload);
        Assert.Equal(Dmc2ContentKind.ContactRouteUpdate, decoded.ContentKind);
        Assert.Empty(decoded.ReplyToLogicalMessageId.ToArray());
        if (count > 0)
        {
            var atom = payload.Atoms[0]; var request = atom.Reconstruct(package.Invite, package.Route);
            Assert.Equal(package.Authorization.CanonicalBytes.ToArray(), request.ExactDca1.ToArray());
            Assert.Equal(B(32, 0x32), request.DirectoryLookupKey.ToArray());
            Assert.Equal(B(32, 0x31), request.RequestNonce.ToArray());
            Assert.Equal(B(32, 0x33), request.MinimumAdh1CoreHash.ToArray());
            Assert.Equal(0UL, request.MinimumAdh1Generation);
            Assert.Empty(atom.ExactCompletedXir1V2.ToArray()); Assert.Empty(atom.ExactCompletedRoute.ToArray());
        }
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void CompletedAtomCarriesItsIndependentXirAndExactSixRecordClosure(bool maximum)
    {
        var package = Package(maximum); var atomBytes = Atom(true, maximum);
        var page = Page(1, [atomBytes], maximum);
        var payload = DeepIdV2ContactRouteHistoryCodec.Decode(page, package.Authorization.NetworkId.Span);
        var atom = Assert.Single(payload.Atoms); Assert.True(atom.IsCompleted);
        Assert.Equal(package.Invite.CanonicalBytes.ToArray(), atom.ExactCompletedXir1V2.ToArray());
        Assert.Equal(package.Route.ExactBytes.ToArray(), atom.ExactCompletedRoute.ToArray());
        Assert.True(MemoryMarshal.TryGetArray(atom.ExactCompletedXir1V2, out var xirExport));
        Assert.True(MemoryMarshal.TryGetArray(atom.ExactCompletedRoute, out var routeExport));
        xirExport.Array!.AsSpan(xirExport.Offset, xirExport.Count).Clear(); routeExport.Array!.AsSpan(routeExport.Offset, routeExport.Count).Clear();
        Assert.Equal(package.Invite.CanonicalBytes.ToArray(), atom.ExactCompletedXir1V2.ToArray());
        Assert.Equal(package.Route.ExactBytes.ToArray(), atom.ExactCompletedRoute.ToArray());
        Assert.True(page.Length <= 29663); Assert.True(atomBytes.Length <= 28635);
        Assert.Equal(1024 + 4 + atomBytes.Length, page.Length);
        var copy = atom.CanonicalBytes.ToArray(); copy.AsSpan().Clear();
        Assert.Equal(atomBytes, atom.CanonicalBytes.ToArray());
    }

    [Theory]
    [InlineData("mode")]
    [InlineData("version")]
    [InlineData("reserved4")]
    [InlineData("reserved77")]
    [InlineData("atom-kind")]
    [InlineData("four-atoms")]
    [InlineData("zero-evidence")]
    [InlineData("request-atoms")]
    [InlineData("request-correlation")]
    [InlineData("unequal-request-cursors")]
    [InlineData("right-generation")]
    [InlineData("zero-cursor-hash")]
    [InlineData("left-xir-generation")]
    [InlineData("outer-length")]
    [InlineData("response-length")]
    [InlineData("pmt-length")]
    [InlineData("nonce")]
    [InlineData("original-dca-network")]
    [InlineData("original-lookup-zero")]
    [InlineData("xir-xra-reference")]
    [InlineData("xir-dca-reference")]
    [InlineData("xir-xrr-generation")]
    [InlineData("truncated")]
    [InlineData("trailing")]
    [InlineData("aggregate")]
    public void HostileFramingRejectsBeforeAnyAuthority(string fault)
    {
        var page = Page(1, [Atom(true, false)]);
        switch (fault)
        {
            case "mode": page[74] = 5; break;
            case "version": page[73] = 2; break;
            case "reserved4": page[76] = 1; break;
            case "reserved77": page[947] = 1; break;
            case "atom-kind": page[1028] = 3; break;
            case "four-atoms": page[75] = 4; break;
            case "zero-evidence": page[75] = 0; break;
            case "request-atoms": page[74] = 4; break;
            case "request-correlation": page = Page(4, []); page[915] = 1; break;
            case "unequal-request-cursors": page = Page(4, []); page[200] ^= 1; break;
            case "right-generation": page[32] ^= 1; break;
            case "zero-cursor-hash": page.AsSpan(88, 32).Clear(); break;
            case "left-xir-generation": page[87] = 1; break;
            case "outer-length": BinaryPrimitives.WriteUInt32BigEndian(page.AsSpan(1024), uint.MaxValue); break;
            case "response-length": BinaryPrimitives.WriteUInt32BigEndian(page.AsSpan(1028 + 1128), uint.MaxValue); break;
            case "pmt-length":
                var responseLength = checked((int)BinaryPrimitives.ReadUInt32BigEndian(page.AsSpan(1028 + 1128)));
                BinaryPrimitives.WriteUInt32BigEndian(page.AsSpan(1028 + 1132 + responseLength + 1254), uint.MaxValue); break;
            case "nonce": page[1029] ^= 1; break;
            case "original-dca-network": page[1028 + 73 + 20] ^= 1; break;
            case "original-lookup-zero": page.AsSpan(1028 + 546, 32).Clear(); break;
            case "xir-xra-reference":
            case "xir-dca-reference":
            case "xir-xrr-generation":
                var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(page.AsSpan(1028 + 1128)));
                var start = 1028 + 1132 + length;
                if (fault == "xir-xrr-generation") page[start + FieldOffset(page.AsSpan(start, 611), 3) + 7] = 1;
                else page[start + FieldOffset(page.AsSpan(start, 611), fault == "xir-xra-reference" ? 18 : 16) + 6] ^= 1;
                break;
            case "truncated": page = page[..^1]; break;
            case "trailing": page = [.. page, 0]; break;
            case "aggregate": page = new byte[32769]; break;
        }
        if (fault is "nonce" or "xir-xra-reference" or "xir-dca-reference")
            Assert.Throws<CryptographicException>(() => DeepIdV2ContactRouteHistoryCodec.Decode(page, Package(false).Authorization.NetworkId.Span));
        else
            Assert.ThrowsAny<FormatException>(() => DeepIdV2ContactRouteHistoryCodec.Decode(page, Package(false).Authorization.NetworkId.Span));
    }

    [Theory]
    [InlineData("xir-identifier")]
    [InlineData("xir-predecessor")]
    [InlineData("xrr-predecessor")]
    [InlineData("generation-skip")]
    [InlineData("policy")]
    [InlineData("reader")]
    [InlineData("publisher")]
    public void CompletedAdjacencyRejectsOriginalXirSubstitutionAndDistinctPredecessorDomains(string fault)
    {
        var prior = Package(false); var next = Adjacent(prior);
        DeepIdV2ContactRouteUpdateVerifier.RequireCompletedHistorySuccessor(prior.Invite, prior.Route, next.Invite, next.Route);
        var invite = next.Invite.CanonicalBytes.ToArray(); var xrr = next.Route.Reachability.CanonicalBytes.ToArray();
        switch (fault)
        {
            case "xir-identifier": invite[FieldOffset(invite, 2)] ^= 1; break;
            case "xir-predecessor": prior.Route.Reachability.CoreHash.Span.CopyTo(invite.AsSpan(FieldOffset(invite, 4))); break;
            case "xrr-predecessor": prior.Invite.ObjectHash.Span.CopyTo(xrr.AsSpan(FieldOffset(xrr, 4))); break;
            case "generation-skip": BinaryPrimitives.WriteUInt64BigEndian(invite.AsSpan(FieldOffset(invite, 3)), 2); break;
            case "policy": invite[FieldOffset(invite, 9)] = 2; BinaryPrimitives.WriteUInt32BigEndian(invite.AsSpan(FieldOffset(invite, 10)), 1); break;
            case "reader": invite[FieldOffset(invite, 11) + 1] = 2; break;
            case "publisher": invite[FieldOffset(invite, 15) + 6] ^= 1; break;
        }
        var changed = new ParsedContactRouteClosure(next.Route.ExactBytes.Span, ContactCodec.Decode("XRR1", xrr),
            next.Route.Authorization, next.Route.Route, next.Route.Successor, next.Route.Projection, next.Route.Selection);
        Assert.Throws<CryptographicException>(() => DeepIdV2ContactRouteUpdateVerifier.RequireCompletedHistorySuccessor(
            prior.Invite, prior.Route, DeepIdV2InviteRendezvousCodec.Decode(invite), changed));
    }

    [Fact]
    public void TypedHistoricalResultsCannotBecomeCurrentOrAuthorFromRawCursor()
    {
        foreach (var type in new[] { typeof(VerifiedDeepIdV2ContactRouteHistory), typeof(VerifiedDeepIdV2ContactRouteHistoryStep),
            typeof(ParsedDeepIdV2ContactRouteHistoryAtom), typeof(ContactRouteHistoryDmc2Payload) })
            Assert.Empty(type.GetConstructors());
        Assert.False(typeof(VerifiedDeepIdV2MailboxRouteClosure).IsAssignableFrom(typeof(VerifiedDeepIdV2ContactRouteHistory)));
        Assert.DoesNotContain(typeof(VerifiedDeepIdV2ContactRouteHistory).GetMethods(), method => method.Name is "EnsureCurrentAsync" or "DispatchAsync" or "SignAsync");
        Assert.DoesNotContain(typeof(ApplicationCoreCodec).GetMethods(), method => method.Name == "CreateContactRouteHistoryPayload");
        var restore = typeof(DeepIdV2ContactRouteUpdateVerifier).GetMethod(nameof(DeepIdV2ContactRouteUpdateVerifier.VerifyRetainedHistoryCheckpointFactsAsync))!;
        Assert.DoesNotContain(restore.GetParameters(), parameter => parameter.ParameterType == typeof(bool) || parameter.Name!.Contains("cursor", StringComparison.OrdinalIgnoreCase));
        Assert.Equal(32768, DeepIdV2ContactRouteHistoryCodec.MaximumPayloadBytes);
        Assert.Equal(33050, ApplicationCoreCodec.MaximumContactRouteUpdateRecordBytes);
        Assert.Equal(16311, 1132 + ContactRouteAuthorityWireCodec.MaximumResponseBytes);
        Assert.Equal(28635, 16311 + 611 + 643 + 4 + 11066);
        Assert.Equal(29663, 1024 + 4 + 28635);
    }

    [Fact]
    public void ProposalOverlapRequiresCompletedKindAndExactOriginalExchange()
    {
        var (request, response) = DeepIdV2ContactRouteRecoveryWireCodecTests.Ordinary();
        var pair = new DeepIdV2ContactRouteRecordedPair(ContactRouteAuthorityWireCodec.EncodeRequest(request),
            ContactRouteAuthorityWireCodec.EncodeResponse(request, response));
        var repeated = new DeepIdV2ContactRouteRecordedPair(pair.ExactRequest.Span, pair.ExactResponse.Span);
        DeepIdV2ContactRouteUpdateVerifier.RequireExactProposalOverlap(true, pair, repeated);
        Assert.Throws<CryptographicException>(() => DeepIdV2ContactRouteUpdateVerifier.RequireExactProposalOverlap(false, pair, repeated));
        Assert.Throws<CryptographicException>(() => DeepIdV2ContactRouteUpdateVerifier.RequireExactProposalOverlap(true, null, repeated));
        var changedRequest = new ContactRouteAuthorityWireRequest(request.NetworkId.Span, B(32, 0x77), request.DirectoryLookupKey.Span,
            request.MinimumAdh1Generation, request.MinimumAdh1CoreHash.Span, request.ExactDca1.Span, request.ExactXra1.Span,
            request.ExactPredecessorXir1V2.Span, request.ExactPredecessorRouteClosure.Span);
        var changedResponse = new ContactRouteAuthorityWireResponse(changedRequest.NetworkId.Span, changedRequest.RequestNonce.Span,
            response.ExactPms2.Span, response.ExactXrc1.Span, response.ExactXss1.Span, response.ExactIssuanceAdh1.Span);
        var changed = new DeepIdV2ContactRouteRecordedPair(ContactRouteAuthorityWireCodec.EncodeRequest(changedRequest),
            ContactRouteAuthorityWireCodec.EncodeResponse(changedRequest, changedResponse));
        Assert.Throws<CryptographicException>(() => DeepIdV2ContactRouteUpdateVerifier.RequireExactProposalOverlap(true, pair, changed));
    }

    [Theory]
    [InlineData("noninitial-original")]
    [InlineData("oversize-invite")]
    [InlineData("oversize-route")]
    [InlineData("xir-xrr-generation")]
    [InlineData("invite-identifier")]
    [InlineData("same-generation-substitution")]
    [InlineData("missing-proposal")]
    [InlineData("proposal-dca")]
    [InlineData("future-proposal-anchor")]
    [InlineData("changed-proposal-anchor")]
    public async Task RetainedCheckpointRejectsStructuralSubstitutionBeforeAuthorityCallbacks(string fault)
    {
        var package = Package(false); var original = OriginalHello(package).CanonicalBytes.ToArray();
        var invite = package.Invite.CanonicalBytes.ToArray(); var route = package.Route.ExactBytes.ToArray();
        // This internal structural witness is not signed verification or native adoption.
        var baseline = DeepIdV2ContactRouteUpdateVerifier.ParseRetainedHistoryCheckpoint(original, invite, route, null);
        Assert.Equal(invite, baseline.ExactCompletedXir1V2.ToArray());
        DeepIdV2ContactRouteRecordedPair? pair = null;
        var expected = "";
        switch (fault)
        {
            case "noninitial-original": original = Event(DeepIdV2ContactRouteHistoryCodec.Decode(Page(4, []), package.Authorization.NetworkId.Span)).CanonicalBytes.ToArray(); expected = "original Hello/Accept"; break;
            case "oversize-invite": invite = new byte[612]; expected = "bounds"; break;
            case "oversize-route": route = new byte[ContactRouteClosureCodec.MaximumEncodedBytes + 1]; expected = "bounds"; break;
            case "xir-xrr-generation":
                BinaryPrimitives.WriteUInt64BigEndian(invite.AsSpan(FieldOffset(invite, 3)), 1);
                package.Invite.ObjectHash.Span.CopyTo(invite.AsSpan(FieldOffset(invite, 4))); expected = "generations differ"; break;
            case "invite-identifier": invite[FieldOffset(invite, 2)] ^= 1; expected = "invite scope"; break;
            case "same-generation-substitution": invite[FieldOffset(invite, 17)] ^= 1; expected = "original completed generation"; break;
            case "missing-proposal":
                (invite, route) = LaterCompletedStructure(package); expected = "cannot bootstrap again"; break;
            case "proposal-dca":
                var dca = package.Authorization.CanonicalBytes.ToArray(); dca[^1] ^= 1;
                pair = RetainedPair(package.Invite.CanonicalBytes.Span, package.Route.ExactBytes.Span, dca);
                expected = "delegation or proposal progress"; break;
            case "future-proposal-anchor":
                var later = LaterCompletedStructure(package); pair = RetainedPair(later.Invite, later.Route);
                expected = "completed anchor"; break;
            case "changed-proposal-anchor":
                var changedAnchor = package.Invite.CanonicalBytes.ToArray(); changedAnchor[FieldOffset(changedAnchor, 17)] ^= 1;
                pair = RetainedPair(changedAnchor, package.Route.ExactBytes.Span); expected = "completed anchor"; break;
        }
        // Missing authority dependencies are intentional: malformed selected sources
        // must reject before the first clock/provider access, not at a later null input.
        var error = await Assert.ThrowsAsync<CryptographicException>(async () =>
            await DeepIdV2ContactRouteUpdateVerifier.VerifyRetainedHistoryCheckpointFactsAsync(
                original, invite, route, pair, null!, null!, null!, null!));
        Assert.Contains(expected, error.Message);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(4)]
    [InlineData(255)]
    public async Task SelectedAtomRejectsIndexOrUnadoptedLeftBeforeAuthorityCallbacks(int selected)
    {
        var package = Package(false); var original = OriginalHello(package);
        var before = DeepIdV2ContactRouteUpdateVerifier.ParseRetainedHistoryCheckpoint(original.CanonicalBytes.Span,
            package.Invite.CanonicalBytes.Span, package.Route.ExactBytes.Span, null);
        var bytes = Page(1, [Atom(false, false)]);
        SHA256.HashData(original.CanonicalBytes.Span).CopyTo(bytes, 40);
        if (selected == 1) bytes[88] ^= 1; // Canonical claimed cursor, not the actual adopted left.
        var payload = DeepIdV2ContactRouteHistoryCodec.Decode(bytes, package.Authorization.NetworkId.Span);
        var message = HistoryEvent(original, payload);
        var error = await Assert.ThrowsAsync<CryptographicException>(async () =>
            await DeepIdV2ContactRouteUpdateVerifier.VerifyHistoryAtomAsync(before, message.CanonicalBytes,
                checked((byte)selected), null!, null!, null!, null!));
        Assert.Contains(selected == 1 ? "left endpoint" : "index", error.Message);
    }

    [Theory]
    [InlineData("nonce")]
    [InlineData("signature")]
    public void SelectedPrefixRequiresExactOriginalProposalEvenWhenCursorHashesMatch(string fault)
    {
        var package = Package(false); var original = OriginalHello(package);
        var bytes = Page(1, [Atom(false, false), Atom(false, false)]);
        SHA256.HashData(original.CanonicalBytes.Span).CopyTo(bytes, 40);
        var payload = DeepIdV2ContactRouteHistoryCodec.Decode(bytes, package.Authorization.NetworkId.Span);
        var first = payload.Atoms[0]; var pair = RetainedPair(package.Invite.CanonicalBytes.Span, package.Route.ExactBytes.Span);
        // Structural prefix comparison only; this does not authenticate the synthetic state.
        var before = new VerifiedDeepIdV2ContactRouteHistory(original, package, package.Invite, package.Route,
            ContactCodec.Decode("XRA1", first.ExactXra1.Span), VerifiedDeepIdV2ContactRouteRecordedHistory.Threshold(pair), pair);
        DeepIdV2ContactRouteUpdateVerifier.RequireHistoryAtomPrefix(before, payload, 2);
        var cursor = before.Cursor.ToArray();
        if (fault == "nonce")
        {
            bytes[1028 + 1] ^= 1;
            bytes[1028 + 1132 + 24] ^= 1; // Keep the untrusted response wrapper nonce canonical.
        }
        else bytes[1028 + 578 + FieldOffset(first.ExactXra1.Span, 16)] ^= 1;
        var changed = DeepIdV2ContactRouteHistoryCodec.Decode(bytes, package.Authorization.NetworkId.Span);
        var changedProposal = ContactCodec.Decode("XRA1", changed.Atoms[0].ExactXra1.Span);
        Assert.Equal(before.Proposal.CoreHash.ToArray(), changedProposal.CoreHash.ToArray());
        Assert.Throws<CryptographicException>(() => DeepIdV2ContactRouteUpdateVerifier.RequireHistoryAtomPrefix(before, changed, 2));
        Assert.Equal(cursor, before.Cursor.ToArray());
    }

    [Fact]
    public void OriginalPairReconstructionOwnsBytesAndReturnsOnlyAnUntrustedExchange()
    {
        var package = Package(false); var payload = DeepIdV2ContactRouteHistoryCodec.Decode(Page(1, [Atom(false, false)]), package.Authorization.NetworkId.Span);
        var atom = Assert.Single(payload.Atoms); var invite = package.Invite.CanonicalBytes.ToArray(); var route = package.Route.ExactBytes.ToArray();
        var pair = DeepIdV2ContactRouteHistoryCodec.ReconstructOriginalPair(atom, invite, route);
        var expectedRequest = ContactRouteAuthorityWireCodec.EncodeRequest(atom.Reconstruct(package.Invite, package.Route));
        var expectedResponse = atom.ExactResponse.ToArray();
        invite.AsSpan().Clear(); route.AsSpan().Clear();
        Assert.Equal(expectedRequest, pair.ExactRequest.ToArray()); Assert.Equal(expectedResponse, pair.ExactResponse.ToArray());
        Assert.True(MemoryMarshal.TryGetArray(pair.ExactRequest, out var exported));
        exported.Array!.AsSpan(exported.Offset, exported.Count).Clear();
        Assert.Equal(expectedRequest, pair.ExactRequest.ToArray());
        Assert.Equal(package.Invite.CanonicalBytes.ToArray(), pair.Request.ExactPredecessorXir1V2.ToArray());
        Assert.Equal(package.Route.ExactBytes.ToArray(), pair.Request.ExactPredecessorRouteClosure.ToArray());
        Assert.False(typeof(VerifiedDeepIdV2MailboxRouteClosure).IsAssignableFrom(pair.GetType()));
    }

    [Theory]
    [InlineData("invite-short")]
    [InlineData("invite-long")]
    [InlineData("route-short")]
    [InlineData("route-long")]
    [InlineData("generation")]
    [InlineData("foreign-network")]
    [InlineData("trailing-route")]
    public void OriginalPairReconstructionRejectsClosedAnchorBoundsAndBindings(string fault)
    {
        var package = Package(false); var atom = Assert.Single(DeepIdV2ContactRouteHistoryCodec.Decode(Page(1, [Atom(false, false)]), package.Authorization.NetworkId.Span).Atoms);
        var invite = package.Invite.CanonicalBytes.ToArray(); var route = package.Route.ExactBytes.ToArray();
        switch (fault)
        {
            case "invite-short": invite = invite[..^1]; break;
            case "invite-long": invite = [.. invite, 0]; break;
            case "route-short": route = new byte[ContactRouteClosureCodec.MinimumEncodedBytes - 1]; break;
            case "route-long": route = new byte[ContactRouteClosureCodec.MaximumEncodedBytes + 1]; break;
            case "generation":
                BinaryPrimitives.WriteUInt64BigEndian(invite.AsSpan(FieldOffset(invite, 3)), 1);
                package.Invite.ObjectHash.Span.CopyTo(invite.AsSpan(FieldOffset(invite, 4))); break;
            case "foreign-network": invite[FieldOffset(invite, 1)] ^= 1; break;
            case "trailing-route": route = [.. route, 0]; break;
        }
        if (fault == "foreign-network")
            Assert.Throws<CryptographicException>(() => DeepIdV2ContactRouteHistoryCodec.ReconstructOriginalPair(atom, invite, route));
        else
            Assert.ThrowsAny<FormatException>(() => DeepIdV2ContactRouteHistoryCodec.ReconstructOriginalPair(atom, invite, route));
    }

    [Fact]
    public void FrozenMachineAllocationMatchesCodecAndKeepsActivationClosed()
    {
        using var json = JsonDocument.Parse(File.ReadAllBytes(FindSpec("contact-route-history-v1.registry.json")));
        var root = json.RootElement; Assert.Equal("DR-0178", root.GetProperty("decision").GetString());
        Assert.False(root.GetProperty("runtimeActivation").GetBoolean()); Assert.True(root.GetProperty("nativePersistenceAllocated").GetBoolean());
        var native = root.GetProperty("nativeAllocation");
        Assert.Equal(608, native.GetProperty("reducer").GetProperty("rootBytes").GetInt32());
        Assert.Equal(576, native.GetProperty("reducer").GetProperty("rootReducerHashOffset").GetInt32());
        Assert.Equal(224, native.GetProperty("F7").GetProperty("valueBytes").GetInt32());
        var bounds = root.GetProperty("bounds");
        Assert.Equal(DeepIdV2ContactRouteHistoryCodec.HeaderBytes, bounds.GetProperty("headerBytes").GetInt32());
        Assert.Equal(DeepIdV2ContactRouteHistoryCodec.MaximumProposalAtomBytes, bounds.GetProperty("maximumProposalAtomBytes").GetInt32());
        Assert.Equal(DeepIdV2ContactRouteHistoryCodec.MaximumCompletedAtomBytes, bounds.GetProperty("maximumCompletedAtomBytes").GetInt32());
        using var vectors = JsonDocument.Parse(File.ReadAllBytes(FindSpec("contact-route-history-v1.vectors.json")));
        var page = Page(4, []);
        foreach (var field in vectors.RootElement.GetProperty("headerFields").EnumerateArray())
        {
            var expected = Convert.FromHexString(field.GetProperty("hex").GetString()!);
            Assert.Equal(expected, page.AsSpan(field.GetProperty("offset").GetInt32(), expected.Length).ToArray());
        }
    }

    private static byte[] Atom(bool completed, bool maximum)
    {
        var package = Package(maximum); var (source, sourceResponse) = DeepIdV2ContactRouteRecoveryWireCodecTests.Ordinary();
        var response = new ContactRouteAuthorityWireResponse(source.NetworkId.Span, source.RequestNonce.Span,
            package.Route.Selection.CanonicalBytes.Span, package.Route.Route.CanonicalBytes.Span,
            package.Route.Successor.CanonicalBytes.Span, sourceResponse.ExactIssuanceAdh1.Span);
        var encoded = ContactRouteAuthorityWireCodec.EncodeResponse(source, response);
        var bytes = new byte[1132 + encoded.Length + (completed ? 1258 + package.Route.Projection.CanonicalBytes.Length : 0)];
        bytes[0] = completed ? (byte)2 : (byte)1; source.RequestNonce.Span.CopyTo(bytes.AsSpan(1));
        source.MinimumAdh1CoreHash.Span.CopyTo(bytes.AsSpan(41)); package.Authorization.CanonicalBytes.Span.CopyTo(bytes.AsSpan(73));
        source.DirectoryLookupKey.Span.CopyTo(bytes.AsSpan(546));
        (completed ? package.Route.Authorization.CanonicalBytes : source.ExactXra1).Span.CopyTo(bytes.AsSpan(578));
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(1128), checked((uint)encoded.Length)); encoded.CopyTo(bytes, 1132);
        if (completed)
        {
            var offset = 1132 + encoded.Length; package.Invite.CanonicalBytes.Span.CopyTo(bytes.AsSpan(offset));
            package.Route.Reachability.CanonicalBytes.Span.CopyTo(bytes.AsSpan(offset + 611));
            BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset + 1254), checked((uint)package.Route.Projection.CanonicalBytes.Length));
            package.Route.Projection.CanonicalBytes.Span.CopyTo(bytes.AsSpan(offset + 1258));
        }
        return bytes;
    }
    private static byte[] Page(int mode, byte[][] atoms, bool maximum = false)
    {
        var package = Package(maximum); var cursor = DeepIdV2ContactRouteHistoryCodec.Cursor(package.Route, package.Route.Authorization, package.Route.Route);
        var bytes = new byte[1024 + atoms.Sum(atom => 4 + atom.Length)]; B(32, 0x51).CopyTo(bytes, 0); B(32, 0x52).CopyTo(bytes, 40);
        bytes[72] = 8; bytes[73] = 1; bytes[74] = checked((byte)mode); bytes[75] = checked((byte)atoms.Length);
        cursor.CopyTo(bytes, 80); cursor.CopyTo(bytes, 192); package.Invite.CanonicalBytes.Span.CopyTo(bytes.AsSpan(304)); var offset = 1024;
        foreach (var atom in atoms) { BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset), checked((uint)atom.Length)); atom.CopyTo(bytes, offset + 4); offset += 4 + atom.Length; }
        return bytes;
    }
    private static ParsedDmc2 Event(ContactRouteHistoryDmc2Payload payload) => ContactCodecValidation.AuthorDmc2(Package(false).Authorization.NetworkId.Span,
        B(32, 0x61), B(32, 0x62), B(32, 0x63), B(32, 0x64), 1, 1000, 2000, Dmc2Flags.None, [], payload);
    private static ParsedDmc2 OriginalHello(ParsedDeepIdV2ContactMailboxRoute package)
    {
        var reference = new byte[38]; "DAB2"u8.CopyTo(reference); BinaryPrimitives.WriteUInt16BigEndian(reference.AsSpan(4), 2); B(32, 0x71).CopyTo(reference, 6);
        var payload = ContactCodecValidation.CreateContactHelloPayload(B(32, 0x51), reference, B(32, 0x72), B(32, 0x73),
            ContactPolicy.AllowRouteUpdates, ContactCodecTests.Records.Xur.CanonicalBytes.Span, package.ExactBytes.Span);
        return ContactCodecValidation.AuthorDmc2(package.Authorization.NetworkId.Span, B(32, 0x74), B(32, 0x75),
            B(32, 0x76), B(32, 0x77), 1, 1000, 2000, Dmc2Flags.None, [], payload);
    }
    private static ParsedDmc2 HistoryEvent(ParsedDmc2 original, ContactRouteHistoryDmc2Payload payload) =>
        ContactCodecValidation.AuthorDmc2(original.NetworkId.Span, B(32, 0x78), original.ConversationId.Span,
            original.SenderAccountId.Span, original.SenderDeviceId.Span, 2, 1000, 2000, Dmc2Flags.None, [], payload);
    private static (byte[] Invite, byte[] Route) LaterCompletedStructure(ParsedDeepIdV2ContactMailboxRoute original)
    {
        var invite = original.Invite.CanonicalBytes.ToArray(); BinaryPrimitives.WriteUInt64BigEndian(invite.AsSpan(FieldOffset(invite, 3)), 1);
        original.Invite.ObjectHash.Span.CopyTo(invite.AsSpan(FieldOffset(invite, 4)));
        var fields = Enumerable.Range(1, 20).Select(original.Route.Reachability.Field).ToArray();
        var generation = new byte[8]; BinaryPrimitives.WriteUInt64BigEndian(generation, 1);
        fields[2] = generation; fields[3] = original.Route.Reachability.CoreHash;
        var xrr = ContactCodecValidation.AuthorRecord("XRR1", fields); var route = original.Route;
        return (invite, ContactRouteClosureCodec.EncodeRecords([xrr, route.Authorization, route.Route, route.Successor, route.Projection, route.Selection]));
    }
    private static DeepIdV2ContactRouteRecordedPair RetainedPair(ReadOnlySpan<byte> anchorInvite, ReadOnlySpan<byte> anchorRoute,
        ReadOnlySpan<byte> dca = default)
    {
        var (request, response) = DeepIdV2ContactRouteRecoveryWireCodecTests.Ordinary();
        var exactDca = dca.IsEmpty ? request.ExactDca1 : dca.ToArray();
        var copied = new ContactRouteAuthorityWireRequest(request.NetworkId.Span, request.RequestNonce.Span, request.DirectoryLookupKey.Span,
            request.MinimumAdh1Generation, request.MinimumAdh1CoreHash.Span, exactDca.Span, request.ExactXra1.Span, anchorInvite, anchorRoute);
        return new(ContactRouteAuthorityWireCodec.EncodeRequest(copied), ContactRouteAuthorityWireCodec.EncodeResponse(copied, response));
    }
    private static (ParsedXir1V2 Invite, ParsedContactRouteClosure Route) Adjacent(ParsedDeepIdV2ContactMailboxRoute prior)
    {
        var invite = prior.Invite.CanonicalBytes.ToArray(); BinaryPrimitives.WriteUInt64BigEndian(invite.AsSpan(FieldOffset(invite, 3)), 1);
        prior.Invite.ObjectHash.Span.CopyTo(invite.AsSpan(FieldOffset(invite, 4)));
        var xrr = prior.Route.Reachability.CanonicalBytes.ToArray(); BinaryPrimitives.WriteUInt64BigEndian(xrr.AsSpan(FieldOffset(xrr, 3)), 1);
        prior.Route.Reachability.CoreHash.Span.CopyTo(xrr.AsSpan(FieldOffset(xrr, 4)));
        BinaryPrimitives.WriteUInt64BigEndian(xrr.AsSpan(FieldOffset(xrr, 17)), DeepIdV2RouteContext.U64(prior.Route.Reachability.Field(17).Span) + 1);
        return (DeepIdV2InviteRendezvousCodec.Decode(invite), new(prior.Route.ExactBytes.Span, ContactCodec.Decode("XRR1", xrr),
            prior.Route.Authorization, prior.Route.Route, prior.Route.Successor, prior.Route.Projection, prior.Route.Selection));
    }
    private static int FieldOffset(ReadOnlySpan<byte> record, int tag)
    {
        var offset = 12;
        while (BinaryPrimitives.ReadUInt16BigEndian(record[offset..]) != tag)
            offset += 8 + checked((int)BinaryPrimitives.ReadUInt32BigEndian(record[(offset + 4)..]));
        return offset + 8;
    }
    private static ParsedDeepIdV2ContactMailboxRoute Package(bool maximum)
    {
        // The older structural fixture deliberately uses independent synthetic
        // XRR capabilities. Completed history additionally checks the actual
        // signed device/route scope, so bind this local fixture to its XRA/XRC.
        var bytes = DeepIdV2ContactMailboxRouteTests.Package(maximum);
        var package = DeepIdV2ContactMailboxRouteCodec.Decode(bytes);
        var route = package.Route;
        var fields = Enumerable.Range(1, 20).Select(route.Reachability.Field).ToArray();
        fields[9] = route.Route.Field(10); fields[10] = route.Authorization.Field(9); fields[12] = route.Authorization.Field(8);
        var xrr = ContactCodecValidation.AuthorRecord("XRR1", fields);
        var closure = ContactRouteClosureCodec.EncodeRecords([xrr, route.Authorization, route.Route, route.Successor, route.Projection, route.Selection]);
        closure.CopyTo(bytes, DeepIdV2ContactMailboxRouteCodec.PrefixBytes);
        return DeepIdV2ContactMailboxRouteCodec.Decode(bytes);
    }
    private static byte[] B(int count, byte value) => Enumerable.Repeat(value, count).ToArray();
    private static string FindSpec(string name)
    {
        for (var directory = new DirectoryInfo(AppContext.BaseDirectory); directory is not null; directory = directory.Parent)
        {
            var candidate = Path.Combine(directory.FullName, "docs", "survival-program", "releases", "v3.0.0", "specs", name);
            if (File.Exists(candidate)) return candidate;
        }
        throw new FileNotFoundException(name);
    }
}
