using System.Buffers.Binary;
using System.Security.Cryptography;
using Sodium;

namespace Deep.Protocol.DeepNative;

/// <summary>
/// Witness-authenticated external recovery checkpoint. Its constructor remains internal and
/// intentionally has no temporary public factory until the normative cold ancestry carrier is
/// frozen; raw DCP/DCS/DCQ bytes cannot mint this fact.
/// </summary>
public sealed class VerifiedRecoveredCutoverCheckpoint
{
    private readonly byte[] _dcp,_dcs,_dcq,_dcl,_drc;
    private readonly byte[] _cutoverFingerprint,_oldSourceFingerprint;

    internal VerifiedRecoveredCutoverCheckpoint(
        OwnedRecord dcp,OwnedRecord dcs,OwnedRecord dcq,
        OwnedRecord dcl,OwnedRecord drc,
        ReadOnlySpan<byte> cutoverFingerprint,
        ReadOnlySpan<byte> oldSourceFingerprint)
    {
        if(cutoverFingerprint.Length!=32||oldSourceFingerprint.Length!=32)
            throw new RecordException(RecordError.InvalidLength,
                "The recovered cutover fingerprints have invalid widths.");
        _dcp=dcp.CanonicalCopy();_dcs=dcs.CanonicalCopy();
        _dcq=dcq.CanonicalCopy();_dcl=dcl.CanonicalCopy();_drc=drc.CanonicalCopy();
        _cutoverFingerprint=cutoverFingerprint.ToArray();
        _oldSourceFingerprint=oldSourceFingerprint.ToArray();
    }

    internal ReadOnlyMemory<byte> Dcp=>_dcp;
    internal ReadOnlyMemory<byte> Dcs=>_dcs;
    internal ReadOnlyMemory<byte> Dcq=>_dcq;
    internal ReadOnlyMemory<byte> Dcl=>_dcl;
    internal ReadOnlyMemory<byte> Drc=>_drc;
    public ReadOnlyMemory<byte> CanonicalDcp=>_dcp.ToArray();
    public ReadOnlyMemory<byte> CanonicalDcs=>_dcs.ToArray();
    public ReadOnlyMemory<byte> CanonicalDcq=>_dcq.ToArray();
    public ReadOnlyMemory<byte> CanonicalDcl=>_dcl.ToArray();
    public ReadOnlyMemory<byte> CanonicalDrc=>_drc.ToArray();
    public ReadOnlyMemory<byte> TransactionId=>CanonicalGrammar.DecodeOwned(
        _dcp,RecordDefinitions.Dcp1).FieldCopy(12);
    public ReadOnlyMemory<byte> ComponentSubject=>CanonicalGrammar.DecodeOwned(
        _dcp,RecordDefinitions.Dcp1).FieldCopy(2);
    public ulong AccountGeneration=>Scalars.UInt64(CanonicalGrammar.DecodeOwned(
        _dcp,RecordDefinitions.Dcp1).FieldSpan(6));
    public ReadOnlyMemory<byte> CutoverFingerprint=>_cutoverFingerprint.ToArray();
    public ReadOnlyMemory<byte> OldProtectedSourceFingerprint=>_oldSourceFingerprint.ToArray();
    public bool NoAuthorityClaim=>true;
}

/// <summary>
/// Complete cold-restore carry input. All bytes are frozen and structurally bounded, but remain
/// untrusted until the high-level verifier completes AEAD, protected HMACs and witness checks.
/// </summary>
public sealed class ColdRecoveryInput
{
    private readonly byte[] _dcp,_dcs,_dcq,_dcl,_dwt,_drc,_rsm;
    private ColdRecoveryInput(
        ReleaseRootManifestPin immutableReleaseRootPin,
        bool terminal,
        ReadOnlySpan<byte> exactDcp1,ReadOnlySpan<byte> exactDcs1,
        ReadOnlySpan<byte> exactDcq1,ReadOnlySpan<byte> exactDcl1,
        ReadOnlySpan<byte> exactDwt1,
            ReadOnlySpan<byte> exactDrc1,ReadOnlySpan<byte> exactRsm723)
    {
        ArgumentNullException.ThrowIfNull(immutableReleaseRootPin);
        if (terminal)
        {
            if (!exactDcp1.IsEmpty || !exactDcs1.IsEmpty || !exactDcq1.IsEmpty ||
                !exactDcl1.IsEmpty || exactDwt1.IsEmpty)
                Invalid("A terminal cold branch must own DWT1 and no candidate/lease rows.");
            CanonicalGrammar.Preflight(exactDwt1,RecordDefinitions.Dwt1);
        }
        else
        {
            if (exactDcp1.IsEmpty || exactDcs1.IsEmpty || exactDcq1.IsEmpty ||
                exactDcl1.IsEmpty || !exactDwt1.IsEmpty)
                Invalid("A nonterminal cold branch must own candidate/lease rows and no DWT1.");
            CanonicalGrammar.Preflight(exactDcp1,RecordDefinitions.Dcp1);
            CanonicalGrammar.Preflight(exactDcs1,RecordDefinitions.Dcs1);
            CanonicalGrammar.Preflight(exactDcq1,RecordDefinitions.Dcq1);
            CanonicalGrammar.Preflight(exactDcl1,RecordDefinitions.Dcl1);
            PreflightRows(CanonicalGrammar.DecodeOwned(exactDcq1,RecordDefinitions.Dcq1).FieldSpan(10),3,758,2806);
            PreflightRows(CanonicalGrammar.DecodeOwned(exactDcl1,RecordDefinitions.Dcl1).FieldSpan(11),3,710,1734);
        }
        CanonicalGrammar.Preflight(exactDrc1,RecordDefinitions.Drc1);
        RecoveryShadow.Preflight(exactRsm723);
        Pin=immutableReleaseRootPin; IsTerminal=terminal;
        _dcp=exactDcp1.ToArray();_dcs=exactDcs1.ToArray();_dcq=exactDcq1.ToArray();
        _dcl=exactDcl1.ToArray();_dwt=exactDwt1.ToArray();
        _drc=exactDrc1.ToArray();_rsm=exactRsm723.ToArray();
        CanonicalGrammar.Preflight(_drc,RecordDefinitions.Drc1);
        RecoveryShadow.Preflight(_rsm);
    }
    public static ColdRecoveryInput CreateNonterminal(
        ReleaseRootManifestPin immutableReleaseRootPin,
        ReadOnlySpan<byte> exactDcp1,ReadOnlySpan<byte> exactDcs1,
        ReadOnlySpan<byte> exactDcq1,ReadOnlySpan<byte> exactDcl1,
        ReadOnlySpan<byte> exactDrc1,ReadOnlySpan<byte> exactRsm723) =>
        new(immutableReleaseRootPin,false,exactDcp1,exactDcs1,exactDcq1,exactDcl1,
            default,exactDrc1,exactRsm723);
    public static ColdRecoveryInput CreateTerminal(
        ReleaseRootManifestPin immutableReleaseRootPin,
        ReadOnlySpan<byte> exactDwt1,ReadOnlySpan<byte> exactDrc1,
        ReadOnlySpan<byte> exactRsm723) =>
        new(immutableReleaseRootPin,true,default,default,default,default,
            exactDwt1,exactDrc1,exactRsm723);
    internal ReleaseRootManifestPin Pin{get;}
    internal bool IsTerminal{get;}
    internal ReadOnlyMemory<byte> Dcp=>_dcp; internal ReadOnlyMemory<byte> Dcs=>_dcs;
    internal ReadOnlyMemory<byte> Dcq=>_dcq; internal ReadOnlyMemory<byte> Dcl=>_dcl;
    internal ReadOnlyMemory<byte> Dwt=>_dwt;
    internal ReadOnlyMemory<byte> Drc=>_drc; internal ReadOnlyMemory<byte> Rsm=>_rsm;
    public bool NoAuthorityClaim=>true;
    private static void PreflightRows(ReadOnlySpan<byte> blob,int count,int minimum,int maximum)
    {var cursor=0;for(var index=0;index<count;index++){if(cursor>blob.Length-4) Invalid("A cold receipt table is truncated.");
      var length=checked((int)BinaryPrimitives.ReadUInt32BigEndian(blob.Slice(cursor,4)));cursor+=4;
      if(length<minimum||length>maximum||cursor>blob.Length-length) Invalid("A cold receipt row is out of bounds.");cursor+=length;}
     if(cursor!=blob.Length) Invalid("A cold receipt table has trailing bytes.");}
    private static void Invalid(string message)=>throw new RecordException(RecordError.InvalidLength,message);
}

/// <summary>
/// Fully verified cold candidate relative to immutable pin and external witness evidence. It is
/// still only a candidate: the consumer owns final reread, CAS, durability and activation.
/// </summary>
public abstract class ColdRecoveryResult : IDisposable
{
    public bool NoAuthorityClaim=>true;
    public abstract void Dispose();
}

public sealed class ColdRecoveryCandidate : ColdRecoveryResult
{
    internal ColdRecoveryCandidate(RecoveryCandidatePlan candidate,
        ReleaseRootRestoreRelative releaseRoot,VerifiedRecoveredIdentityContext identity,
        VerifiedRecoveredCutoverCheckpoint checkpoint)
    {Candidate=candidate;ReleaseRoot=releaseRoot;Identity=identity;ExternalCheckpoint=checkpoint;}
    public RecoveryCandidatePlan Candidate{get;}
    public ReleaseRootRestoreRelative ReleaseRoot{get;}
    public VerifiedRecoveredIdentityContext Identity{get;}
    public VerifiedRecoveredCutoverCheckpoint ExternalCheckpoint{get;}
    public override void Dispose()=>Candidate.Dispose();
}

/// <summary>
/// Authenticated terminal recovery state. It carries no candidate DPL, publication surface,
/// or activation authority.
/// </summary>
public sealed class TerminalColdRecoveryState : ColdRecoveryResult
{
    private readonly byte[] _cutoverFingerprint,_oldSourceFingerprint;
    internal TerminalColdRecoveryState(
        ReleaseRootRestoreRelative releaseRoot,
        VerifiedRecoveredIdentityContext identity,
        ReadOnlySpan<byte> cutoverFingerprint,
        ReadOnlySpan<byte> oldSourceFingerprint)
    {ReleaseRoot=releaseRoot;Identity=identity;
     _cutoverFingerprint=cutoverFingerprint.ToArray();
     _oldSourceFingerprint=oldSourceFingerprint.ToArray();}
    public ReleaseRootRestoreRelative ReleaseRoot{get;}
    public VerifiedRecoveredIdentityContext Identity{get;}
    public ReadOnlyMemory<byte> CutoverFingerprint=>_cutoverFingerprint.ToArray();
    public ReadOnlyMemory<byte> OldProtectedSourceFingerprint=>_oldSourceFingerprint.ToArray();
    public override void Dispose() { }
}

public static partial class RecoveryVerifier
{
    public static async ValueTask<ColdRecoveryResult> OpenColdAsync(
        ColdRecoveryInput input,RecoveryProtectorProvider protectorProvider,
        RecoveryProviderRegistry providerRegistry,RecoveryNonceLatch nonceLatch,
        IProtectedHmacProvider protectedHmacProvider,
        ulong transactionTimeUnixSeconds,CancellationToken cancellationToken=default)
    {
        ArgumentNullException.ThrowIfNull(input);ArgumentNullException.ThrowIfNull(protectorProvider);
        ArgumentNullException.ThrowIfNull(providerRegistry);
        ArgumentNullException.ThrowIfNull(nonceLatch);ArgumentNullException.ThrowIfNull(protectedHmacProvider);
        if(transactionTimeUnixSeconds==0) throw new RecordException(RecordError.InvalidField,"Cold recovery time is zero.");
        cancellationToken.ThrowIfCancellationRequested();
        var registryRequest=RecoveryEngine.CreateColdProviderRegistryRequest(input);
        var providerContext=await RecoveryProviderRegistryContext.ReadAsync(
            providerRegistry,registryRequest,cancellationToken).ConfigureAwait(false);
        var candidate=await RecoveryEngine.OpenColdPayloadAsync(
            input,providerContext,protectorProvider,nonceLatch,protectedHmacProvider,
            cancellationToken).ConfigureAwait(false);
        try
        {
            await RevalidateProviderAsync(providerContext,providerRegistry,registryRequest,
                nonceLatch,candidate,cancellationToken).ConfigureAwait(false);
            if(input.IsTerminal)
            {
                var terminalRows=candidate.Artifacts.Where(value=>value.ArtifactType==ArtifactType.Dwt1).ToArray();
                if(terminalRows.Length!=1 || !CanonicalGrammar.FixedEquals(
                    terminalRows[0].CanonicalBytes.Span,input.Dwt.Span))
                    throw new RecordException(RecordError.InvalidField,
                    "The terminal cold tag differs from authenticated DRM20 DWT1.");
            }
            else if(candidate.Artifacts.Any(value=>value.ArtifactType==ArtifactType.Dwt1))
                throw new RecordException(RecordError.InvalidField,
                    "The nonterminal cold tag cannot authenticate a terminal DRM20.");
            var release=candidate.RestoreReleaseRootAncestry(
                input.Pin,input.IsTerminal?default:input.Dcl,transactionTimeUnixSeconds);
            var releaseContext=new VerifiedCurrentReleaseRootContext(release);
            var expectedReleaseFingerprint=releaseContext.Fingerprint.ToArray();
            if(input.Rsm.Span[96]==2)
            {
                var genesis=candidate.RestoreGenesisReleaseAncestry(
                    input.Pin,transactionTimeUnixSeconds);
                var dwh=candidate.Manifest.WitnessHeadHistory;
                var historyCount=BinaryPrimitives.ReadUInt16BigEndian(dwh.Slice(166,2));
                expectedReleaseFingerprint=GenesisReleaseContext.ComputeFingerprint(
                    candidate.Manifest.RfcSourceTuple.Slice(16,32),genesis.Root,
                    genesis.Delegations,dwh.Slice(168,checked(historyCount*342)),
                    historyCount,dwh.Slice(dwh.Length-64,32),
                    GenesisReleaseContext.ComputeAuthorityHead(
                        genesis.Root,genesis.Delegations[^1]));
            }
            if(!CanonicalGrammar.FixedEquals(
                input.Rsm.Span.Slice(595,32),expectedReleaseFingerprint))
                throw new RecordException(RecordError.InvalidField,
                    "The recovered ReleaseRoot fingerprint differs from RSM2.");
            var identity=candidate.RestoreRecoveredIdentityContext(transactionTimeUnixSeconds);
            if(!CanonicalGrammar.FixedEquals(input.Rsm.Span.Slice(627,32),identity.Fingerprint.Span))
                throw new RecordException(RecordError.InvalidField,
                    "The recovered identity fingerprint differs from RSM2.");
            VerifyOldProtectedSource(candidate,input,expectedReleaseFingerprint,
                identity,providerContext);
            if(input.IsTerminal)
            {
                if(!release.IsTerminal)
                    throw new RecordException(RecordError.InvalidField,
                        "The terminal cold tag restored a nonterminal ReleaseRoot.");
                await RevalidateProviderAsync(providerContext,providerRegistry,registryRequest,
                    nonceLatch,candidate,cancellationToken).ConfigureAwait(false);
                candidate.Dispose();
                return new TerminalColdRecoveryState(release,identity,
                    input.Rsm.Span.Slice(659,32),input.Rsm.Span.Slice(691,32));
            }
            var checkpoint=RecoveryExternalCheckpointVerifier.Verify(candidate,identity.Identity,release,
                input.Dcp.Span,input.Dcs.Span,input.Dcq.Span,input.Dcl.Span,input.Drc.Span,
                input.Rsm.Span,transactionTimeUnixSeconds);
            await RevalidateProviderAsync(providerContext,providerRegistry,registryRequest,
                nonceLatch,candidate,cancellationToken).ConfigureAwait(false);
            return new ColdRecoveryCandidate(candidate,release,identity,checkpoint);
        }
        catch{candidate.Dispose();throw;}
    }

    private static async ValueTask RevalidateProviderAsync(
        RecoveryProviderRegistryContext providerContext,
        RecoveryProviderRegistry providerRegistry,
        RecoveryProviderRegistryRequest registryRequest,
        RecoveryNonceLatch nonceLatch,
        RecoveryCandidatePlan candidate,
        CancellationToken cancellationToken)
    {
        await providerContext.RevalidateAsync(providerRegistry,registryRequest,cancellationToken)
            .ConfigureAwait(false);
        await providerContext.RevalidateLatchAsync(nonceLatch,candidate.LatchKey,
            candidate.LatchValue,cancellationToken).ConfigureAwait(false);
    }

    private static void VerifyOldProtectedSource(
        RecoveryCandidatePlan candidate,
        ColdRecoveryInput input,
        ReadOnlySpan<byte> expectedReleaseFingerprint,
        VerifiedRecoveredIdentityContext identity,
        RecoveryProviderRegistryContext providerContext)
    {
        var rsm=input.Rsm.Span;
        byte[] terminalReference;
        byte[] leaseReference;
        ulong leaseExpires;
        if(input.IsTerminal)
        {
            terminalReference=CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
                ArtifactType.Dwt1,input.Dwt.Span));
            leaseReference=new byte[38];
            leaseExpires=0;
        }
        else if(rsm[96]==1)
        {
            var dcl=CanonicalGrammar.DecodeOwned(input.Dcl.Span,RecordDefinitions.Dcl1);
            terminalReference=new byte[38];
            leaseReference=CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(
                ArtifactType.Dcl1,input.Dcl.Span));
            leaseExpires=Scalars.UInt64(dcl.FieldSpan(13));
        }
        else
        {
            terminalReference=new byte[38];
            leaseReference=new byte[38];
            leaseExpires=0;
        }
        var oldSourceHash=RecoveryContextFingerprint.OldProtectedSource(
            rsm[96],candidate.Manifest.RfcSourceTuple.Slice(58,38),rsm.Slice(135,32),
            expectedReleaseFingerprint,identity.Fingerprint.Span,rsm.Slice(659,32),input.IsTerminal,
            terminalReference,leaseReference,leaseExpires,
            providerContext.ProtectedStateHmacKeyId,providerContext.RecoveryNonceLatchKeyId,
            candidate.Capsule.ProtectorKeyId.Span);
        var oldSourceMatches=CanonicalGrammar.FixedEquals(rsm.Slice(691,32),oldSourceHash);
        CryptographicOperations.ZeroMemory(oldSourceHash);
        if(!oldSourceMatches)
            throw new RecordException(RecordError.InvalidField,
                "The cold recovery old protected source differs from the sealed provider registry.");
    }
}

internal static class RecoveryExternalCheckpointVerifier
{
    internal static VerifiedRecoveredCutoverCheckpoint Verify(
        RecoveryCandidatePlan candidate,
        VerifiedIdentityRelative identity,
        ReleaseRootRestoreRelative releaseRoot,
        ReadOnlySpan<byte> exactDcp,
        ReadOnlySpan<byte> exactDcs,
        ReadOnlySpan<byte> exactDcq,
        ReadOnlySpan<byte> exactDcl,
        ReadOnlySpan<byte> exactDrc,
        ReadOnlySpan<byte> exactRsm,
        ulong transactionTimeUnixSeconds)
    {
        var dcp=CanonicalGrammar.DecodeOwned(exactDcp,RecordDefinitions.Dcp1);
        var dcs=CanonicalGrammar.DecodeOwned(exactDcs,RecordDefinitions.Dcs1);
        var dcq=CanonicalGrammar.DecodeOwned(exactDcq,RecordDefinitions.Dcq1);
        var dcl=CanonicalGrammar.DecodeOwned(exactDcl,RecordDefinitions.Dcl1);
        var drc=CanonicalGrammar.DecodeOwned(exactDrc,RecordDefinitions.Drc1);
        var dcm=Find(candidate,ArtifactType.Dcm1,RecordDefinitions.Dcm1);
        var projection=candidate.PinCoreProjection.Span;
        var dcpRef=Ref(ArtifactType.Dcp1,dcp.CanonicalSpan);
        var dcsRef=Ref(ArtifactType.Dcs1,dcs.CanonicalSpan);
        var dcqRef=Ref(ArtifactType.Dcq1,dcq.CanonicalSpan);
        var drcRef=Ref(ArtifactType.Drc1,drc.CanonicalSpan);
        var draRows=candidate.Artifacts.Where(value=>value.ArtifactType==ArtifactType.Dra1).ToArray();
        if(draRows.Length>1) Invalid("DRM2 contains duplicate DRA1 rows.");
        var draRef=draRows.Length==0?new byte[38]:draRows[0].ArtifactReference.ToArray();
        var latest=releaseRoot.LatestDelegation;
        var latestDwdRef=Ref(ArtifactType.Dwd1,latest.Delegation.CanonicalBytes.Span);
        var authorityHead=CanonicalGrammar.Sha256Domain(
            "Deep/Cutover/V1/release-root-authority-head",releaseRoot.AuthorityTuple.CanonicalTuple.Span);

        Equal(candidate.Capsule.CanonicalBytes.Span,drc.CanonicalSpan,"candidate DRC1");
        Equal(drc.FieldSpan(1),projection[..16],"DRC1 network");
        Equal(drc.FieldSpan(3),candidate.Manifest.RfcSourceTuple.Slice(128,32),"DRC1 transaction");
        Equal(drc.FieldSpan(5),projection.Slice(72,38),"DRC1 DCM");
        Equal(drc.FieldSpan(6),projection.Slice(190,38),"DRC1 DRS");
        Equal(dcp.FieldSpan(1),projection[..16],"DCP1 network");
        Equal(dcp.FieldSpan(2),drc.FieldSpan(2),"DCP1 component subject");
        Equal(dcp.FieldSpan(3),projection.Slice(16,2),"DCP1 component kind");
        Equal(dcp.FieldSpan(6),projection.Slice(18,8),"DCP1 account generation");
        Equal(dcp.FieldSpan(7),projection.Slice(72,38),"DCP1 DCM");
        Equal(dcp.FieldSpan(8),projection.Slice(142,8),"DCP1 DRS revision");
        Equal(dcp.FieldSpan(9),projection.Slice(150,8),"DCP1 DRS count");
        Equal(dcp.FieldSpan(10),projection.Slice(158,32),"DCP1 DRS head");
        Equal(dcp.FieldSpan(11),projection.Slice(190,38),"DCP1 DRS");
        Equal(dcp.FieldSpan(12),drc.FieldSpan(3),"DCP1 transaction");
        Equal(dcp.FieldSpan(18),draRef,"DCP1 DRA");
        Equal(dcp.FieldSpan(19),projection.Slice(110,32),"DCP1 reset key hash");
        Equal(dcp.FieldSpan(15),latestDwdRef,"DCP1 DWD");
        Equal(dcp.FieldSpan(16),latest.Delegation.Record.FieldSpan(4),"DCP1 witness epoch");
        Equal(dcp.FieldSpan(20),drcRef,"DCP1 capsule");
        Equal(projection.Slice(228,38),CanonicalGrammar.EncodeReference(
            releaseRoot.ReleaseRoot.CurrentTransitionReference),"DPL ReleaseRoot transition");
        Equal(projection.Slice(110,32),dcm.FieldSpan(11),"DPL/DCM reset key hash");

        Equal(dcs.FieldSpan(1),dcp.FieldSpan(1),"DCS1 network");
        Equal(dcs.FieldSpan(2),dcp.FieldSpan(6),"DCS1 account generation");
        Equal(dcs.FieldSpan(3),dcm.FieldSpan(2),"DCS1 reset ID");
        Equal(dcs.FieldSpan(6),dcp.FieldSpan(7),"DCS1 DCM");
        Equal(dcs.FieldSpan(7),dcp.FieldSpan(12),"DCS1 transaction");
        Equal(dcs.FieldSpan(8),latestDwdRef,"DCS1 DWD");
        Equal(dcs.FieldSpan(9),latest.Delegation.Record.FieldSpan(4),"DCS1 witness epoch");
        BindComponentRow(dcs,dcp,dcpRef);

        var now=transactionTimeUnixSeconds;
        Window(dcp.FieldSpan(13),dcp.FieldSpan(14),now,"DCP1");
        Window(dcs.FieldSpan(12),dcs.FieldSpan(13),now,"DCS1");
        var reset=identity.Authority.GetKeyAuthority(KeyScope.ResetControl);
        if(reset.IsTerminal) Invalid("The recovered reset-control key is terminal.");
        VerifySignature(dcp.FieldSpan(21),CanonicalGrammar.GetSigningBytes(
            dcp,"Deep/Cutover/V1/component-checkpoint"),reset.CurrentEd25519PublicKey.Span);
        VerifySignature(dcs.FieldSpan(14),CanonicalGrammar.GetSigningBytes(
            dcs,"Deep/Cutover/V1/deployment-set"),reset.CurrentEd25519PublicKey.Span);

        Equal(dcq.FieldSpan(1),dcp.FieldSpan(1),"DCQ1 network");
        Equal(dcq.FieldSpan(3),dcs.FieldSpan(4),"DCQ1 sequence");
        Equal(dcq.FieldSpan(4),dcsRef,"DCQ1 DCS");
        Equal(dcq.FieldSpan(6),latestDwdRef,"DCQ1 DWD");
        Equal(dcq.FieldSpan(7),latest.Delegation.Record.FieldSpan(15),"DCQ1 set root");
        Equal(dcq.FieldSpan(8),latest.Delegation.Record.FieldSpan(4),"DCQ1 witness epoch");
        Window(dcq.FieldSpan(11),dcq.FieldSpan(12),now,"DCQ1");
        VerifyQuorumReceipts(dcq,latest,releaseRoot,authorityHead,now);

        if(releaseRoot.FreshLease is null) Invalid("The recovered ReleaseRoot has no fresh DCL1.");
        Equal(dcl.CanonicalSpan,releaseRoot.FreshLease!.CanonicalBytes.Span,
            "DCL1 sealed fresh lease");
        Equal(dcl.FieldSpan(1),dcq.FieldSpan(1),"DCL1 network");
        Equal(dcl.FieldSpan(2),dcq.FieldSpan(2),"DCL1 deployment subject");
        Equal(dcl.FieldSpan(3),dcq.FieldSpan(3),"DCL1 sequence");
        Equal(dcl.FieldSpan(4),dcsRef,"DCL1 DCS");
        Equal(dcl.FieldSpan(5),latestDwdRef,"DCL1 DWD");
        Equal(dcl.FieldSpan(6),authorityHead,"DCL1 authority head");
        Equal(dcl.FieldSpan(7),dcq.FieldSpan(7),"DCL1 set root");
        Equal(dcl.FieldSpan(8),dcq.FieldSpan(8),"DCL1 epoch");
        if(now>=Scalars.UInt64(dcl.FieldSpan(13)))
            throw new RecordException(RecordError.Expired,"The external DCL1 is no longer live.");
        _=dcqRef;
        return new VerifiedRecoveredCutoverCheckpoint(dcp,dcs,dcq,dcl,drc,
            exactRsm.Slice(659,32),exactRsm.Slice(691,32));
    }

    private static void VerifyQuorumReceipts(
        OwnedRecord dcq,WitnessDelegationRelativeFact latest,
        ReleaseRootRestoreRelative root,ReadOnlySpan<byte> authorityHead,ulong now)
    {
        if(dcq.FieldSpan(9)[0]!=3) Invalid("DCQ1 must contain exactly three receipts.");
        var blob=dcq.FieldSpan(10);var cursor=0;var references=new byte[114];
        var leafPayload=new byte[116];
        ReadOnlySpan<byte> previousId=default;
        for(var index=0;index<3;index++)
        {
            if(cursor>blob.Length-4) Invalid("DCQ1 receipt framing is truncated.");
            var length=checked((int)BinaryPrimitives.ReadUInt32BigEndian(blob.Slice(cursor,4)));cursor+=4;
            if(length is <758 or >2806 || cursor>blob.Length-length) Invalid("DCQ1 receipt length is invalid.");
            var receipt=CanonicalGrammar.DecodeOwned(blob.Slice(cursor,length),RecordDefinitions.Dcn1);cursor+=length;
            for(var tag=1;tag<=5;tag++) Equal(receipt.FieldSpan(tag),dcq.FieldSpan(tag),$"DCQ1/DCN1 field {tag}");
            Equal(receipt.FieldSpan(6),dcq.FieldSpan(7),"DCQ1/DCN1 witness-set root");
            Equal(receipt.FieldSpan(7),dcq.FieldSpan(8),"DCQ1/DCN1 witness epoch");
            Equal(receipt.FieldSpan(8),dcq.FieldSpan(6),"DCQ1/DCN1 DWD");
            if(Scalars.UInt64(receipt.FieldSpan(9))!=root.ReleaseRoot.CurrentGeneration)
                Invalid("DCN1 ReleaseRoot generation is stale.");
            Equal(receipt.FieldSpan(10),CanonicalGrammar.EncodeReference(
                root.ReleaseRoot.CurrentTransitionReference),"DCN1 ReleaseRoot transition");
            var terminal=root.IsTerminal;
            if((receipt.FieldSpan(12)[0]!=0)!=terminal) Invalid("DCN1 terminal state is stale.");
            var terminalReference=root.ReleaseRoot.PendingTerminalRevocation is null
                ? new byte[38]
                : Ref(ArtifactType.Krf1,
                    root.ReleaseRoot.PendingTerminalRevocation.CanonicalBytes.Span);
            Equal(receipt.FieldSpan(11),terminalReference,"DCN1 terminal KRF");
            Equal(receipt.FieldSpan(13),authorityHead,"DCN1 authority head");
            var witnessId=receipt.FieldSpan(14).ToArray();
            if(index!=0 && previousId.SequenceCompareTo(witnessId)>=0) Invalid("DCQ1 receipt IDs are not sorted.");
            previousId=witnessId;
            var descriptor=latest.Descriptors.SingleOrDefault(value=>
                CanonicalGrammar.FixedEquals(value.WitnessId.Span,witnessId));
            if(descriptor is null) Invalid("A DCN1 signer is outside the current DWD1.");
            var previousSize=Scalars.UInt64(receipt.FieldSpan(15));
            var treeSize=Scalars.UInt64(receipt.FieldSpan(17));
            if(treeSize>latest.Delegation.MaximumTreeSize || previousSize>treeSize ||
                receipt.FieldSpan(26)[0]!=(byte)DurabilityClass.FsyncReplicated)
                Invalid("A DCN1 tree or durability scalar is invalid.");
            leafPayload.AsSpan().Clear();
            dcq.FieldSpan(2).CopyTo(leafPayload);
            dcq.FieldSpan(3).CopyTo(leafPayload.AsSpan(32));
            dcq.FieldSpan(4).CopyTo(leafPayload.AsSpan(40));
            dcq.FieldSpan(5).CopyTo(leafPayload.AsSpan(78));
            WitnessTreeVerifier.VerifyInclusion(WitnessTreeVerifier.Leaf(leafPayload),
                Scalars.UInt64(receipt.FieldSpan(19)),treeSize,receipt.FieldSpan(21),receipt.FieldSpan(18));
            WitnessTreeVerifier.VerifyConsistency(previousSize,receipt.FieldSpan(16),treeSize,
                receipt.FieldSpan(18),receipt.FieldSpan(23),WitnessTreeVerifier.EmptyRoot(
                latest.Delegation.WitnessEpoch,witnessId,latest.Delegation.MaximumTreeSize));
            Window(receipt.FieldSpan(24),receipt.FieldSpan(25),now,"DCN1");
            VerifySignature(receipt.FieldSpan(27),CanonicalGrammar.GetSigningBytes(
                receipt,"Deep/Cutover/V1/witness-receipt"),descriptor!.Ed25519PublicKey.Span);
            Ref(ArtifactType.Dcn1,receipt.CanonicalSpan).CopyTo(references,index*38);
        }
        if(cursor!=blob.Length) Invalid("DCQ1 has trailing receipt bytes.");
        Equal(dcq.FieldSpan(13),GenesisQuorumStateVerifier.ComputeQuorumDigest(
            dcq.FieldSpan(2),dcq.FieldSpan(3),dcq.FieldSpan(4),dcq.FieldSpan(5),references),
            "DCQ1 digest");
    }

    private static void BindComponentRow(OwnedRecord dcs,OwnedRecord dcp,ReadOnlySpan<byte> dcpRef)
    {
        var rows=dcs.FieldSpan(11);var kind=BinaryPrimitives.ReadUInt16BigEndian(dcp.FieldSpan(3));
        var found=false;for(var offset=0;offset<rows.Length;offset+=104)
            if(BinaryPrimitives.ReadUInt16BigEndian(rows.Slice(offset,2))==kind)
            {Equal(rows.Slice(offset+2,32),dcp.FieldSpan(2),"DCS1 component subject");
             Equal(rows.Slice(offset+34,38),dcpRef,"DCS1 component checkpoint");
             Equal(rows.Slice(offset+72,32),dcp.FieldSpan(17),"DCS1 schema fingerprint");found=true;}
        if(!found) Invalid("DCS1 omits the recovered component row.");
    }

    private static OwnedRecord Find(RecoveryCandidatePlan candidate,ArtifactType type,RecordDefinition definition)
    {var rows=candidate.Artifacts.Where(value=>value.ArtifactType==type).ToArray();
     if(rows.Length!=1) Invalid($"DRM2 requires exactly one {type} row.");
     return CanonicalGrammar.DecodeOwned(rows[0].CanonicalBytes.Span,definition);}
    private static byte[] Ref(ArtifactType type,ReadOnlySpan<byte> canonical)=>
        CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(type,canonical));
    private static void Window(ReadOnlySpan<byte> issued,ReadOnlySpan<byte> expires,ulong now,string name)
    {var i=Scalars.UInt64(issued);var e=Scalars.UInt64(expires);
     if(i==0||e<=i||now<i||now>=e) throw new RecordException(RecordError.Expired,$"{name} is outside its live window.");}
    private static void VerifySignature(ReadOnlySpan<byte> signature,ReadOnlySpan<byte> message,ReadOnlySpan<byte> key)
    {try{if(!PublicKeyAuth.VerifyDetached(signature.ToArray(),message.ToArray(),key.ToArray()))
        throw new RecordException(RecordError.InvalidSignature,"An external checkpoint signature is invalid.");}
     catch(CryptographicException ex){throw new RecordException(RecordError.InvalidSignature,ex.Message);}}
    private static void Equal(ReadOnlySpan<byte> actual,ReadOnlySpan<byte> expected,string name)
    {if(!CanonicalGrammar.FixedEquals(actual,expected)) Invalid($"The {name} differs.");}
    private static void Invalid(string message)=>throw new RecordException(RecordError.InvalidField,message);
}
