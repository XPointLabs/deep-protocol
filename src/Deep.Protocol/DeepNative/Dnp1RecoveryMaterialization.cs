namespace Deep.Protocol.DeepNative;

/// <summary>Data-only candidate DPL bytes and exact old/new source tuples.</summary>
public sealed class RecoveryMaterializationPlan
{
    private readonly byte[] _canonical;
    private readonly byte[] _oldSource;
    private readonly byte[] _newSource;
    internal RecoveryMaterializationPlan(
        ReadOnlySpan<byte> canonical, ReadOnlySpan<byte> oldSource, ReadOnlySpan<byte> newSource)
    { _canonical=canonical.ToArray(); _oldSource=oldSource.ToArray(); _newSource=newSource.ToArray(); }
    public ReadOnlyMemory<byte> CanonicalCandidateDpl=>_canonical.ToArray();
    public ReadOnlyMemory<byte> ExpectedOldDplAndProtectedSourceTuple=>_oldSource.ToArray();
    public ReadOnlyMemory<byte> CandidateDplArtifactReference=>_newSource.ToArray();
    public bool NoAuthorityClaim=>true;
}

public static partial class RecoveryVerifier
{
    /// <summary>Authors the first candidate DPL from a verified genesis quorum.</summary>
    public static async ValueTask<RecoveryMaterializationPlan> MaterializeGenesisCandidateDplAsync(
        GenesisAuthorCreatedPlan created,
        GenesisVerifiedQuorumPlan quorum,
        GenesisProtectedKeySetContext keySet,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken=default)
    {
        ArgumentNullException.ThrowIfNull(created);
        ArgumentNullException.ThrowIfNull(quorum);
        ArgumentNullException.ThrowIfNull(keySet);
        ArgumentNullException.ThrowIfNull(hmacProvider);
        cancellationToken.ThrowIfCancellationRequested();
        var plan=created.Candidate;
        var identity=plan.Identity;
        if(!CanonicalGrammar.FixedEquals(identity.BaseIdentity.Network,keySet.Network) ||
           !CanonicalGrammar.FixedEquals(identity.BaseIdentity.ResetId,keySet.ResetId) ||
           identity.BaseIdentity.AccountGeneration!=keySet.AccountGeneration ||
           identity.Scope.ComponentKind!=keySet.ComponentKind ||
           !CanonicalGrammar.FixedEquals(identity.Scope.ComponentSubject,keySet.ComponentSubject))
            Invalid("The genesis DPL key set differs from the candidate axes.");
        var manifestBytes=plan.Candidate.Manifest.ToArray();
        var artifactCount=System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(
            manifestBytes.AsSpan(6,2));
        using var manifest=RecoveryManifestParser.DecodeOwned(manifestBytes,artifactCount);
        var projection=manifest.PinCoreProjection.ToArray();
        var dcp=plan.ComponentCheckpoints.Single(value=>
            value.ComponentKind==(ushort)identity.Scope.ComponentKind);
        var dcpRef=Ref(ArtifactType.Dcp1,dcp.CanonicalBytes.Span);
        var dcsRef=Ref(ArtifactType.Dcs1,plan.DeploymentSet.CanonicalBytes.Span);
        var dcqRef=Ref(ArtifactType.Dcq1,quorum.QuorumReceipt.CanonicalBytes.Span);
        var selection=quorum.Selection.CanonicalSelection.Span;
        if(!CanonicalGrammar.FixedEquals(selection.Slice(461,38),dcqRef) ||
           !CanonicalGrammar.FixedEquals(selection.Slice(516,32),identity.ProtectedStateHmacKeyId))
            Invalid("The genesis quorum selection differs from the candidate or shared HMAC role.");
        var fields=new ReadOnlyMemory<byte>[18];
        for(var tag=1;tag<=11;tag++) fields[tag-1]=Projection(tag);
        fields[11]=dcpRef;fields[12]=dcsRef;fields[13]=dcqRef;
        for(var tag=15;tag<=17;tag++) fields[tag-1]=Projection(tag);
        fields[17]=new byte[32];
        var candidateBytes=CanonicalGrammar.Encode(RecordDefinitions.Dpl1,fields);
        var decoded=CanonicalGrammar.DecodeOwned(candidateBytes,RecordDefinitions.Dpl1);
        var unsignedDefinition=RecordDefinitions.Dpl1 with
        { Fields=RecordDefinitions.Dpl1.Fields.Take(17).ToArray(),MinimumLength=12,
          OmittedSigningFieldIndexes=new HashSet<int>() };
        var unsigned=CanonicalGrammar.Encode(unsignedDefinition,
            Enumerable.Range(1,17).Select(tag=>(ReadOnlyMemory<byte>)decoded.FieldCopy(tag)).ToArray());
        var returned=await hmacProvider.ComputeTagAsync(new ProtectedHmacRequest(
            "Deep/ProtectedState/V1/DPL1",ArtifactRegistry.ProtectedHmacSha256,
            keySet.DplKeyId,unsigned),cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var tagBytes=returned.ToArray();
        try
        {
            if(tagBytes.Length!=32) Invalid("The genesis DPL HMAC provider returned a wrong-length tag.");
            fields[17]=tagBytes;
            candidateBytes=CanonicalGrammar.Encode(RecordDefinitions.Dpl1,fields);
            var verified=CanonicalGrammar.DecodeOwned(candidateBytes,RecordDefinitions.Dpl1);
            if(!CanonicalGrammar.FixedEquals(verified.FieldSpan(18),tagBytes))
                Invalid("The genesis DPL changed after authoring.");
            return new RecoveryMaterializationPlan(candidateBytes,new byte[70],
                Ref(ArtifactType.Dpl1,verified.CanonicalSpan));
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(tagBytes);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(manifestBytes);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(projection);
        }

        ReadOnlyMemory<byte> Projection(int tag)
        {
            var lengths=new[]{16,2,8,38,8,38,32,8,8,32,38,38,1,7};
            var index=tag<=11?tag-1:tag-4;var offset=0;
            for(var cursor=0;cursor<index;cursor++) offset+=lengths[cursor];
            return projection.AsMemory(offset,lengths[index]);
        }
    }

    public static async ValueTask<RecoveryMaterializationPlan> MaterializeGenesisReplayCandidateDplAsync(
        RecoveryCandidatePlan candidate,
        VerifiedGenesisArtifactSet artifactSet,
        GenesisVerifiedQuorumPlan quorum,
        GenesisIdentityContext identity,
        GenesisProtectedKeySetContext keySet,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken=default)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        ArgumentNullException.ThrowIfNull(artifactSet);
        ArgumentNullException.ThrowIfNull(quorum);
        ArgumentNullException.ThrowIfNull(identity);
        ArgumentNullException.ThrowIfNull(keySet);
        ArgumentNullException.ThrowIfNull(hmacProvider);
        cancellationToken.ThrowIfCancellationRequested();
        if(!CanonicalGrammar.FixedEquals(candidate.Capsule.CanonicalBytes.Span,
                artifactSet.Artifacts[0].Span) ||
           !CanonicalGrammar.FixedEquals(identity.BaseIdentity.Network,keySet.Network) ||
           !CanonicalGrammar.FixedEquals(identity.BaseIdentity.ResetId,keySet.ResetId) ||
           identity.BaseIdentity.AccountGeneration!=keySet.AccountGeneration ||
           identity.Scope.ComponentKind!=keySet.ComponentKind ||
           !CanonicalGrammar.FixedEquals(identity.Scope.ComponentSubject,keySet.ComponentSubject))
            Invalid("The restored genesis DPL inputs differ from their sealed axes.");
        var projection=candidate.PinCoreProjection.ToArray();
        var dcp=CanonicalGrammar.DecodeOwned(
            artifactSet.Artifacts[(int)identity.Scope.ComponentKind].Span,RecordDefinitions.Dcp1);
        var dcs=CanonicalGrammar.DecodeOwned(artifactSet.Artifacts[5].Span,RecordDefinitions.Dcs1);
        var dcpRef=Ref(ArtifactType.Dcp1,dcp.CanonicalSpan);
        var dcsRef=Ref(ArtifactType.Dcs1,dcs.CanonicalSpan);
        var dcqRef=Ref(ArtifactType.Dcq1,quorum.QuorumReceipt.CanonicalBytes.Span);
        if(!CanonicalGrammar.FixedEquals(quorum.Selection.CanonicalSelection.Span.Slice(461,38),dcqRef))
            Invalid("The restored genesis GQS1 differs from DCQ1.");
        var fields=new ReadOnlyMemory<byte>[18];
        for(var tag=1;tag<=11;tag++) fields[tag-1]=Projection(tag);
        fields[11]=dcpRef;fields[12]=dcsRef;fields[13]=dcqRef;
        for(var tag=15;tag<=17;tag++) fields[tag-1]=Projection(tag);
        fields[17]=new byte[32];
        var candidateBytes=CanonicalGrammar.Encode(RecordDefinitions.Dpl1,fields);
        var decoded=CanonicalGrammar.DecodeOwned(candidateBytes,RecordDefinitions.Dpl1);
        var unsignedDefinition=RecordDefinitions.Dpl1 with
        { Fields=RecordDefinitions.Dpl1.Fields.Take(17).ToArray(),MinimumLength=12,
          OmittedSigningFieldIndexes=new HashSet<int>() };
        var unsigned=CanonicalGrammar.Encode(unsignedDefinition,
            Enumerable.Range(1,17).Select(tag=>(ReadOnlyMemory<byte>)decoded.FieldCopy(tag)).ToArray());
        var returned=await hmacProvider.ComputeTagAsync(new ProtectedHmacRequest(
            "Deep/ProtectedState/V1/DPL1",ArtifactRegistry.ProtectedHmacSha256,
            keySet.DplKeyId,unsigned),cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var tagBytes=returned.ToArray();
        try
        {
            if(tagBytes.Length!=32) Invalid("The restored genesis DPL provider returned a wrong-length tag.");
            fields[17]=tagBytes;
            candidateBytes=CanonicalGrammar.Encode(RecordDefinitions.Dpl1,fields);
            var verified=CanonicalGrammar.DecodeOwned(candidateBytes,RecordDefinitions.Dpl1);
            return new RecoveryMaterializationPlan(candidateBytes,new byte[70],
                Ref(ArtifactType.Dpl1,verified.CanonicalSpan));
        }
        finally
        {
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(tagBytes);
            System.Security.Cryptography.CryptographicOperations.ZeroMemory(projection);
        }

        ReadOnlyMemory<byte> Projection(int tag)
        {
            var lengths=new[]{16,2,8,38,8,38,32,8,8,32,38,38,1,7};
            var index=tag<=11?tag-1:tag-4;var offset=0;
            for(var cursor=0;cursor<index;cursor++) offset+=lengths[cursor];
            return projection.AsMemory(offset,lengths[index]);
        }
    }

    /// <summary>Authors one exact candidate DPL HMAC transcript after all external refs bind.</summary>
    public static async ValueTask<RecoveryMaterializationPlan> MaterializeCandidateDplAsync(
        RecoveryCandidatePlan candidate,
        VerifiedRecoveredCutoverCheckpoint externalCheckpoint,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken=default)
    {
        ArgumentNullException.ThrowIfNull(externalCheckpoint);
        return await MaterializeCandidateDplCoreAsync(
            candidate,externalCheckpoint.Dcp,externalCheckpoint.Dcs,externalCheckpoint.Dcq,
            externalCheckpoint.Dcl,externalCheckpoint.Drc,
            hmacProvider,cancellationToken).ConfigureAwait(false);
    }

    private static async ValueTask<RecoveryMaterializationPlan> MaterializeCandidateDplCoreAsync(
        RecoveryCandidatePlan candidate,
        ReadOnlyMemory<byte> canonicalDcp,
        ReadOnlyMemory<byte> canonicalDcs,
        ReadOnlyMemory<byte> canonicalDcq,
        ReadOnlyMemory<byte> canonicalDcl,
        ReadOnlyMemory<byte> canonicalDrc,
        IProtectedHmacProvider hmacProvider,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(candidate);
        ArgumentNullException.ThrowIfNull(hmacProvider);
        cancellationToken.ThrowIfCancellationRequested();
        var projection=candidate.PinCoreProjection.ToArray();
        var dcp=CanonicalGrammar.DecodeOwned(canonicalDcp.Span,RecordDefinitions.Dcp1);
        var dcs=CanonicalGrammar.DecodeOwned(canonicalDcs.Span,RecordDefinitions.Dcs1);
        var dcq=CanonicalGrammar.DecodeOwned(canonicalDcq.Span,RecordDefinitions.Dcq1);
        var dcl=CanonicalGrammar.DecodeOwned(canonicalDcl.Span,RecordDefinitions.Dcl1);
        var drc=CanonicalGrammar.DecodeOwned(canonicalDrc.Span,RecordDefinitions.Drc1);
        var dcpRef=Ref(ArtifactType.Dcp1,dcp.CanonicalSpan);
        var dcsRef=Ref(ArtifactType.Dcs1,dcs.CanonicalSpan);
        var dcqRef=Ref(ArtifactType.Dcq1,dcq.CanonicalSpan);
        if(!CanonicalGrammar.FixedEquals(dcp.FieldSpan(1),projection.AsSpan(0,16)) ||
           Scalars.UInt16(dcp.FieldSpan(3))!=System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(projection.AsSpan(16,2)) ||
           Scalars.UInt64(dcp.FieldSpan(6))!=System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(projection.AsSpan(18,8)) ||
           !CanonicalGrammar.FixedEquals(dcp.FieldSpan(7),projection.AsSpan(72,38)) ||
           !CanonicalGrammar.FixedEquals(dcp.FieldSpan(11),projection.AsSpan(190,38)) ||
           !CanonicalGrammar.FixedEquals(dcp.FieldSpan(12),dcs.FieldSpan(7)) ||
           !CanonicalGrammar.FixedEquals(dcs.FieldSpan(1),projection.AsSpan(0,16)) ||
           !CanonicalGrammar.FixedEquals(dcs.FieldSpan(6),projection.AsSpan(72,38)) ||
           !CanonicalGrammar.FixedEquals(dcq.FieldSpan(1),projection.AsSpan(0,16)) ||
           !CanonicalGrammar.FixedEquals(dcq.FieldSpan(4),dcsRef) ||
           (!CanonicalGrammar.FixedEquals(
                candidate.Capsule.CanonicalBytes.Span,drc.CanonicalSpan) ||
                !CanonicalGrammar.FixedEquals(dcp.FieldSpan(20),Ref(ArtifactType.Drc1,drc.CanonicalSpan)) ||
                !CanonicalGrammar.FixedEquals(dcp.FieldSpan(2),drc.FieldSpan(2)) ||
                !CanonicalGrammar.FixedEquals(dcp.FieldSpan(12),drc.FieldSpan(3)) ||
                !CanonicalGrammar.FixedEquals(drc.FieldSpan(3),candidate.Manifest.RfcSourceTuple.Slice(128,32))) ||
           (!CanonicalGrammar.FixedEquals(dcl.FieldSpan(1),dcq.FieldSpan(1)) ||
                !CanonicalGrammar.FixedEquals(dcl.FieldSpan(2),dcq.FieldSpan(2)) ||
                !CanonicalGrammar.FixedEquals(dcl.FieldSpan(3),dcq.FieldSpan(3)) ||
                !CanonicalGrammar.FixedEquals(dcl.FieldSpan(4),dcsRef) ||
                !CanonicalGrammar.FixedEquals(dcl.FieldSpan(5),dcq.FieldSpan(6)) ||
                !CanonicalGrammar.FixedEquals(dcl.FieldSpan(7),dcq.FieldSpan(7)) ||
                !CanonicalGrammar.FixedEquals(dcl.FieldSpan(8),dcq.FieldSpan(8))))
            Invalid("The external DCP/DCS/DCQ tuple differs from the recovered pin core.");
        var fields=new ReadOnlyMemory<byte>[18]; var offset=0;
        for(var tag=1;tag<=11;tag++) fields[tag-1]=SliceProjection(tag);
        fields[11]=dcpRef; fields[12]=dcsRef; fields[13]=dcqRef;
        for(var tag=15;tag<=17;tag++) fields[tag-1]=SliceProjection(tag);
        fields[17]=new byte[32];
        var candidateBytes=CanonicalGrammar.Encode(RecordDefinitions.Dpl1,fields);
        var record=CanonicalGrammar.DecodeOwned(candidateBytes,RecordDefinitions.Dpl1);
        var unsignedDefinition=RecordDefinitions.Dpl1 with
        { Fields=RecordDefinitions.Dpl1.Fields.Take(17).ToArray(), MinimumLength=12,
          OmittedSigningFieldIndexes=new HashSet<int>() };
        var unsigned=CanonicalGrammar.Encode(unsignedDefinition,
            Enumerable.Range(1,17).Select(tag=>(ReadOnlyMemory<byte>)record.FieldCopy(tag)).ToArray());
        var keyId=candidate.Manifest.RfcProtectedKeyId.ToArray();
        var returned=await hmacProvider.ComputeTagAsync(new ProtectedHmacRequest(
            "Deep/ProtectedState/V1/DPL1",ArtifactRegistry.ProtectedHmacSha256,keyId,unsigned),cancellationToken).ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        var tagBytes=returned.ToArray();
        if(tagBytes.Length!=32) Invalid("The candidate DPL HMAC provider returned a wrong-length tag.");
        fields[17]=tagBytes;
        candidateBytes=CanonicalGrammar.Encode(RecordDefinitions.Dpl1,fields);
        var verified=CanonicalGrammar.DecodeOwned(candidateBytes,RecordDefinitions.Dpl1);
        // Re-querying is forbidden: local verification is by matching the frozen authored tag.
        if(!CanonicalGrammar.FixedEquals(verified.FieldSpan(18),tagBytes))
            Invalid("The candidate DPL changed after authoring.");
        var oldSource=new byte[70];
        candidate.Manifest.RfcSourceTuple.Slice(58,38).CopyTo(oldSource);
        candidate.Manifest.RfcSourceTuple.Slice(96,32).CopyTo(oldSource.AsSpan(38));
        var newSource=Ref(ArtifactType.Dpl1,verified.CanonicalSpan);
        return new RecoveryMaterializationPlan(candidateBytes,oldSource,newSource);

        ReadOnlyMemory<byte> SliceProjection(int tag)
        {
            var lengths=new[]{16,2,8,38,8,38,32,8,8,32,38,38,1,7};
            var index=tag<=11?tag-1:tag-4;
            offset=0; for(var i=0;i<index;i++) offset+=lengths[i];
            return projection.AsMemory(offset,lengths[index]);
        }
    }

    private static byte[] Ref(ArtifactType type,ReadOnlySpan<byte> canonical)=>
        CanonicalGrammar.EncodeReference(CanonicalGrammar.ComputeReference(type,canonical));
    private static void Invalid(string message)=>
        throw new RecordException(RecordError.InvalidField,message);
}
