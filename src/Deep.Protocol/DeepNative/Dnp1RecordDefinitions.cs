using System.Buffers.Binary;

namespace Deep.Protocol.DeepNative;

internal static class RecordDefinitions
{
    private static FieldDefinition F(string name, int length) =>
        FieldDefinition.Fixed(name, length);

    private static FieldDefinition V(string name, int minimum, int maximum) =>
        new(name, minimum, maximum);

    private static IReadOnlySet<int> O(params int[] indexes) => new HashSet<int>(indexes);

    private static RecordDefinition Public(
        string magic, ushort version, int minimum, int maximum,
        FieldDefinition[] fields, params int[] omitted) =>
        new(magic, version, ArtifactRegistry.IdentityAuthV1Ed25519,
            RecordClass.PublicAuthenticated, minimum, maximum, fields, O(omitted));

    private static RecordDefinition Unsigned(
        string magic, ushort version, int minimum, int maximum,
        FieldDefinition[] fields) =>
        new(magic, version, ArtifactRegistry.CommittedUnsigned,
            RecordClass.PublicCommittedUnsigned, minimum, maximum, fields, O());

    private static RecordDefinition Protected(
        string magic, int minimum, int maximum,
        FieldDefinition[] fields, bool aead = false) =>
        new(magic, 1,
            aead ? ArtifactRegistry.ProtectedAead : ArtifactRegistry.ProtectedHmacSha256,
            aead ? RecordClass.ProtectedAead : RecordClass.ProtectedHmac,
            minimum, maximum, fields, O());

    internal static RecordDefinition Dpa1 { get; } = Public("DPA1", 1, 644, 644,
        [F("network",16),F("accountGeneration",8),F("certificateGeneration",8),F("predecessor",38),
         F("accountEd",32),F("deviceIssuerEd",32),F("revocationEd",32),F("resetEd",32),F("revocationHandle",32),
         F("createdAt",8),F("policyGeneration",8),F("minimumSuite",2),F("accountSignature",64),
         F("issuerPop",64),F("revocationPop",64),F("resetPop",64)], 13,14,15,16);

    internal static RecordDefinition Dpd1 { get; } = Public("DPD1", 1, 776, 776,
        [F("network",16),F("accountHash",32),F("accountGeneration",8),F("deviceId",32),F("deviceGeneration",8),
         F("deviceEd",32),F("deviceX",32),F("revocationHandle",32),F("issuerTransitionGeneration",8),
         F("issuerTransition",38),F("issuerKeyHash",32),F("drsRevision",8),F("drs",38),F("drsCount",8),
         F("drsHead",32),F("issuedAt",8),F("expiresAt",8),F("capabilities",8),F("suite",2),
         F("predecessor",38),F("xPopTranscriptHash",32),F("devicePop",64),F("issuerSignature",64)], 21,22,23);

    internal static RecordDefinition Dpm1 { get; } = Public("DPM1", 1, 670, 670,
        [F("network",16),F("accountHash",32),F("accountGeneration",8),F("deviceId",32),F("device",38),
         F("ownerId",32),F("roleGeneration",8),F("mailboxEd",32),F("revocationHandle",32),F("drsRevision",8),
         F("drs",38),F("drsCount",8),F("drsHead",32),F("issuedAt",8),F("expiresAt",8),F("capabilities",8),
         F("predecessor",38),F("deviceSignature",64),F("mailboxPop",64)], 18,19);

    internal static RecordDefinition Drt1 { get; } = Unsigned("DRT1", 1, 179, 179,
        [F("accountHash",32),F("targetKind",1),F("revocationHandle",32),F("targetGeneration",8),F("certificate",38),F("targetNotAfter",8)]);

    internal static RecordDefinition Drs1 { get; } = Public("DRS1", 1, 356, 63844,
        [F("network",16),F("accountHash",32),F("accountGeneration",8),F("revision",8),F("issuedAt",8),
         F("keyTransitionGeneration",8),F("keyTransition",38),F("keyHash",32),F("entryCount",2),V("entries",0,63488),
         F("head",32),F("signature",64)], 12);

    internal static RecordDefinition Krt1 { get; } = Public("KRT1", 1, 412, 412,
        [F("network",16),F("scope",1),F("accountHash",32),F("accountGeneration",8),F("generation",8),
         F("predecessor",38),F("oldKeyHash",32),F("newEd",32),F("effectiveAt",8),F("action",1),
         F("oldSignature",64),F("newPop",64)], 11,12);

    internal static RecordDefinition Krf1 { get; } = Public("KRF1", 1, 300, 300,
        [F("network",16),F("scope",1),F("accountHash",32),F("accountGeneration",8),F("generation",8),
         F("predecessor",38),F("oldKeyHash",32),F("effectiveAt",8),F("action",1),F("oldSignature",64)], 10);

    internal static RecordDefinition Dcm1 { get; } = Public("DCM1", 1, 812, 812,
        [F("network",16),F("resetId",32),F("resetGeneration",8),F("accountGeneration",8),F("account",38),
         F("drsRevision",8),F("drsCount",8),F("drsHead",32),F("drs",38),F("resetTransitionGeneration",8),
         F("resetKeyHash",32),F("resetTransition",38),F("predecessor",38),F("activationAt",8),F("components",168),
         F("createdAt",8),F("nonce",32),F("resetSignature",64),F("accountPop",64)], 18,19);

    internal static RecordDefinition Dra1 { get; } = Public("DRA1", 1, 788, 788,
        [F("network",16),F("oldAccountGeneration",8),F("oldAccount",38),F("oldDcmGeneration",8),F("oldDcm",38),
         F("oldDrsCount",8),F("oldDrsHead",32),F("oldDrs",38),F("newAccountGeneration",8),F("newAccount",38),
         F("newDcmGeneration",8),F("newDcm",38),F("cutoffAt",8),F("nonce",32),F("reason",2),F("oldResetKeyHash",32),
         F("newAccountKeyHash",32),F("newResetKeyHash",32),F("oldSignature",64),F("newAccountPop",64),F("newResetPop",64)], 19,20,21);

    internal static RecordDefinition Dwd1 { get; } = Public("DWD1", 1, 1217, 1217,
        [F("network",16),F("generation",8),F("predecessor",38),F("epoch",8),F("validFrom",8),F("validUntil",8),
         F("checkpointTtl",8),F("leaseTtl",8),F("maximumTreeSize",8),F("componentMask",8),F("subjectPolicyHash",32),
         F("finalHeadsHash",32),F("witnessCount",1),F("descriptors",464),F("setRoot",32),F("releaseTransition",38),
         F("releaseSignature",64),F("pop1",64),F("pop2",64),F("pop3",64),F("pop4",64)],17,18,19,20,21);

    internal static RecordDefinition Dcp1 { get; } = Public("DCP1", 1, 706, 706,
        [F("network",16),F("componentSubject",32),F("componentKind",2),F("sequence",8),F("predecessor",38),
         F("accountGeneration",8),F("dcm",38),F("drsRevision",8),F("drsCount",8),F("drsHead",32),F("drs",38),
         F("transactionId",32),F("issuedAt",8),F("expiresAt",8),F("dwd",38),F("witnessEpoch",8),F("schemaFingerprint",32),
         F("dra",38),F("resetKeyHash",32),F("capsule",38),F("signature",64)],21);

    internal static RecordDefinition Dcs1 { get; } = Public("DCS1", 1, 839, 839,
        [F("network",16),F("accountGeneration",8),F("resetId",32),F("sequence",8),F("predecessor",38),F("dcm",38),
         F("transactionId",32),F("dwd",38),F("witnessEpoch",8),F("componentCount",1),F("components",416),
         F("createdAt",8),F("expiresAt",8),F("signature",64)],14);

    internal static RecordDefinition Dct1 { get; } = Public("DCT1", 1, 414, 414,
        [F("network",16),F("deploymentSubject",32),F("expectedSequence",8),F("expectedDcs",38),F("candidateDcs",38),
         F("transactionId",32),F("requestNonce",32),F("issuedAt",8),F("expiresAt",8),F("dwd",38),F("signature",64)],11);

    internal static RecordDefinition Dcn1 { get; } = Public("DCN1", 1, 758, 2806,
        [F("network",16),F("deploymentSubject",32),F("sequence",8),F("dcs",38),F("dct",38),F("setRoot",32),
         F("witnessEpoch",8),F("dwd",38),F("releaseRootGeneration",8),F("releaseRootTransition",38),F("terminalKrf",38),
         F("terminalState",1),F("releaseRootAuthorityHeadHash",32),F("witnessId",32),F("previousTreeSize",8),
         F("previousTreeRoot",32),F("treeSize",8),F("treeRoot",32),F("leafIndex",8),F("inclusionCount",1),
         V("inclusionProof",0,1024),F("consistencyCount",1),V("consistencyProof",0,1024),F("issuedAt",8),
         F("leaseExpiresAt",8),F("durabilityClass",1),F("signature",64)],27);

    internal static RecordDefinition Dcq1 { get; } = Public("DCQ1", 1, 375, 8805,
        [F("network",16),F("deploymentSubject",32),F("sequence",8),F("dcs",38),F("dct",38),F("dwd",38),F("setRoot",32),
         F("witnessEpoch",8),F("receiptCount",1),V("receipts",0,7812),F("issuedAt",8),F("expiresAt",8),F("digest",32)]);

    internal static RecordDefinition Dhl1 { get; } = Public("DHL1", 1, 710, 1734,
        [F("network",16),F("deploymentSubject",32),F("sequence",8),F("dcs",38),F("setRoot",32),F("witnessEpoch",8),
         F("dwd",38),F("releaseRootGeneration",8),F("releaseRootTransition",38),F("terminalKrf",38),F("terminalState",1),
         F("releaseRootAuthorityHeadHash",32),F("witnessId",32),F("priorTreeSize",8),F("priorTreeRoot",32),
         F("currentTreeSize",8),F("currentTreeRoot",32),F("proofCount",1),V("proof",0,1024),F("queryNonce",32),
         F("issuedAt",8),F("expiresAt",8),F("signature",64)],23);

    internal static RecordDefinition Dcl1 { get; } = Public("DCL1", 1, 409, 5623,
        [F("network",16),F("deploymentSubject",32),F("sequence",8),F("dcs",38),F("dwd",38),F("releaseRootAuthorityHeadHash",32),
         F("setRoot",32),F("witnessEpoch",8),F("queryNonce",32),F("receiptCount",1),V("receipts",0,5202),
         F("issuedAt",8),F("expiresAt",8),F("digest",32)]);

    internal static RecordDefinition Dwl1 { get; } = Protected("DWL1", 708, 708,
        [F("network",16),F("deploymentSubject",32),F("dwdGeneration",8),F("dwd",38),F("setRoot",32),F("heads",288),
         F("sequence",8),F("dcs",38),F("dcq",38),F("dcl",38),F("leaseExpiresAt",8),F("forkLatch",1),F("reserved",7),F("hmac",32)]);

    internal static RecordDefinition Drc1 { get; } = Protected("DRC1", 482, 33554914,
        [F("network",16),F("componentSubject",32),F("transactionId",32),F("accountGeneration",8),F("dcm",38),F("drs",38),
         F("pinCoreHash",32),F("shadowHash",32),F("artifactCount",2),F("plaintextLength",8),F("ciphertextLength",8),
         F("nonce",24),F("keyId",32),F("createdAt",8),F("retainUntil",8),V("ciphertext",0,33554432),F("tag",16)], true);

    internal static RecordDefinition Dpl1 { get; } = Protected("DPL1", 576, 576,
        [F("network",16),F("componentKind",2),F("accountGeneration",8),F("account",38),F("dcmGeneration",8),F("dcm",38),
         F("resetKeyHash",32),F("drsRevision",8),F("drsCount",8),F("drsHead",32),F("drs",38),F("dcp",38),F("dcs",38),
         F("dcq",38),F("releaseTransition",38),F("forkLatch",1),F("reserved",7),F("hmac",32)]);

    internal static RecordDefinition Dbg1 { get; } = Protected("DBG1", 296, 296,
        [F("network",16),F("componentKind",2),F("schemaGeneration",8),F("schemaFingerprint",32),F("dcp",38),F("dcm",38),
         F("initializedAt",8),F("dpl",38),F("hmac",32)]);

    internal static RecordDefinition Rib1 { get; } = Protected("RIB1", 772, 772,
        [F("network",16),F("resetId",32),F("dcp",38),F("dcm",38),F("routeStateKey",32),F("accountHash",32),F("account",38),
         F("deviceId",32),F("device",38),F("ownerId",32),F("mailbox",38),F("drsCount",8),F("drsHead",32),F("drs",38),
         F("msm",38),F("mrlSequence",8),F("mrlRoot",32),F("dgSource",38),F("bindingGeneration",8),F("hmac",32)]);

    internal static RecordDefinition Xib1 { get; } = Protected("XIB1", 452, 452,
        [F("network",16),F("resetId",32),F("dcp",38),F("dcm",38),F("msm",38),F("sequence",8),F("root",32),
         F("pmc2",38),F("lineage",32),F("targetRouter",32),F("scheduleGeneration",8),F("hmac",32)]);

    internal static RecordDefinition Dnr1 { get; } = Public("DNR1", 1, 756, 756,
        [F("network",16),F("ownerId",32),F("mailbox",38),F("pma",38),F("pmaGeneration",8),F("pmr",38),F("pmrGeneration",8),
         F("issuerKeyHash",32),F("routerId",32),F("routerGeneration",8),F("routerEd",32),F("routerX",32),F("revocationHandle",32),
         F("roles",8),F("capabilities",8),F("issuedAt",8),F("expiresAt",8),F("predecessor",38),F("xPopHash",32),F("routerPop",64),F("issuerSignature",64)],19,20,21);

    internal static RecordDefinition Mrl2 { get; } = Unsigned("MRL2", 2, 326, 326,
        [F("network",16),F("epoch",8),F("generation",8),F("routerId",32),F("dnrc",38),F("roles",8),F("capabilities",8),
         F("anchorDpcGeneration",8),F("anchorDpc",38),F("validFrom",8),F("validUntil",8),F("predecessor",38)]);

    internal static RecordDefinition Rip2 { get; } = Unsigned("RIP2", 2, 573, 957,
        [F("network",16),F("resetId",32),F("msmSequence",8),F("epoch",8),F("protocolVersion",2),
         F("descriptorGeneration",8),F("memberCount",4),F("paddedLeafCount",4),F("leafIndex",4),F("mrlRoot",32),
         F("mrlLength",4),F("mrl",326),F("siblingCount",1),V("siblings",0,384)]);

    internal static RecordDefinition Dpc1 { get; } = Public("DPC1", 1, 430, 680,
        [F("network",16),F("routerId",32),F("dnrc",38),F("generation",8),F("predecessor",38),F("issuedAt",8),F("expiresAt",8),
         F("capabilities",8),F("endpointKind",1),V("address",3,253),F("port",2),F("currentSpki",32),F("nextSpki",32),F("flags",8),F("signature",64)],15);

    internal static RecordDefinition Dpr1 { get; } = Public("DPR1", 1, 408, 408,
        [F("network",16),F("sender",32),F("recipient",32),F("senderDpc",38),F("recipientDpc",38),F("requestId",32),
         F("issuedAt",8),F("expiresAt",8),F("operation",2),F("prq",38),F("signature",64)],11);

    internal static RecordDefinition Dps1 { get; } = Public("DPS1", 1, 444, 444,
        [F("network",16),F("sender",32),F("recipient",32),F("senderDpc",38),F("recipientDpc",38),F("requestId",32),
         F("dpr",38),F("mrr",38),F("issuedAt",8),F("expiresAt",8),F("signature",64)],11);

    internal static RecordDefinition Mrlc { get; } = Protected("MRLC", 898, 16778114,
        [F("network",16),F("resetId",32),F("dcp",38),F("dcs",38),F("dcq",38),F("dwl",38),F("drsRevision",8),F("drs",38),
         F("mng",38),F("membershipClosureHash",32),F("msm",38),F("msmSequence",8),F("memberCount",4),F("mrlRoot",32),
         F("pma",38),F("pmaGeneration",8),F("pmaEpoch",8),F("pmr",38),F("pmrGeneration",8),F("pmrHead",32),F("pmrSnapshotHash",32),
         F("dnrcSelectionHash",32),F("artifactEntryCount",4),F("catalogLength",8),F("catalogHash",32),V("catalog",0,16777216),F("hmac",32)]);

    internal static RecordDefinition Dpj1 { get; } = Protected("DPJ1", 609, 609,
        [F("network",16),F("sender",32),F("recipient",32),F("requestId",32),F("journalKey",32),F("dpr",38),F("prq",38),
         F("operation",2),F("createdAt",8),F("expiresAt",8),F("phase",1),F("deliveryAuthorized",1),F("terminalStale",1),
         F("requestHash",32),F("outcomeHash",32),F("dps",38),F("mrr",38),F("retainedUntil",8),F("forkLatch",1),F("reserved",7),F("hmac",32)]);

    internal static RecordDefinition Rrm1 { get; } = Public("RRM1", 1, 332, 332,
        [F("network",16),F("manifestGeneration",8),F("environmentResetId",32),F("releaseRootGeneration",8),
         F("releaseRootEd",32),F("activationAt",8),F("componentMask",8),F("schemaFingerprint",32),
         F("manifestSignerKeyId",32),F("manifestSignature",64)],10);

    internal static RecordDefinition Rrl1 { get; } = Protected("RRL1", 502, 502,
        [F("network",16),F("genesisRrm",38),F("currentGeneration",8),F("currentPublic",32),F("currentTransition",38),
         F("terminalKrf",38),F("terminalState",1),F("forkLatch",1),F("latestDwdGeneration",8),F("latestDwd",38),
         F("latestWitnessEpoch",8),F("chainEntryCount",2),F("chainCheckpointHash",32),F("terminalDwt",38),
         F("protectedStateKeyId",32),F("hmac",32)]);

    internal static RecordDefinition Dwt1 { get; } = Public("DWT1", 1, 714, 714,
        [F("network",16),F("priorDwd",38),F("witnessEpoch",8),F("releaseRootGeneration",8),F("releaseRootTransition",38),
         F("krf",38),F("effectiveAt",8),F("receiptCount",1),F("receipts",435),F("digest",32)]);

    internal static RecordDefinition Dxr1 { get; } = Protected("DXR1", 573, 573,
        [F("phase",1),F("role",1),F("network",16),F("operationId",32),F("subjectProjectionHash",32),
         F("holderX",32),F("issuerEphemeralPublic",32),F("nonce",32),F("nonceLedgerKey",32),
         F("issuedAt",8),F("expiresAt",8),F("verifiedAt",8),F("transcriptHash",32),F("subject",38),
         F("currentSourceFingerprint",32),F("protectedStateKeyId",32),F("forkLatch",1),
         F("retainedUntil",8),F("hmac",32)]);

    private static readonly IReadOnlyDictionary<string, RecordDefinition> ByMagic =
        new[] { Dpa1,Dpd1,Dpm1,Drt1,Drs1,Krt1,Krf1,Dcm1,Dra1,Dwd1,Dcp1,Dcs1,Dct1,Dcn1,Dcq1,Dhl1,Dcl1,Dwl1,Drc1,Dpl1,Dbg1,Rib1,Xib1,Dnr1,Mrl2,Rip2,Dpc1,Dpr1,Dps1,Mrlc,Dpj1,Rrm1,Rrl1,Dwt1,Dxr1 }
            .ToDictionary(static value => value.Magic, StringComparer.Ordinal);

    internal static RecordDefinition Get(string magic) =>
        ByMagic.TryGetValue(magic, out var definition)
            ? definition
            : throw new RecordException(RecordError.InvalidMagic, "The DNP1 record magic is unknown.");

    internal static void ValidateDynamic(ReadOnlySpan<byte> encoded, RecordDefinition definition)
    {
        switch (definition.Magic)
        {
            case "DRS1":
            {
                var count = BinaryPrimitives.ReadUInt16BigEndian(Field(encoded, 9));
                if (Field(encoded, 10).Length != checked(count * 62) ||
                    count > 1024)
                    Invalid("The DRS1 entry table is malformed.");
                break;
            }
            case "DCN1":
                Proof(Field(encoded,20)[0], Field(encoded,21));
                Proof(Field(encoded,22)[0], Field(encoded,23));
                break;
            case "DHL1":
                Proof(Field(encoded,18)[0], Field(encoded,19));
                break;
            case "DCQ1":
                Receipts(Field(encoded,9)[0], Field(encoded,10), 2806);
                break;
            case "DCL1":
                Receipts(Field(encoded,10)[0], Field(encoded,11), 1734);
                break;
            case "DWD1":
                if (Field(encoded,13)[0] != 4) Invalid("DWD1 requires four witnesses.");
                break;
            case "DCS1":
                if (Field(encoded,10)[0] != 4) Invalid("DCS1 requires four components.");
                break;
            case "DRC1":
            {
                var artifactCount = BinaryPrimitives.ReadUInt16BigEndian(Field(encoded, 9));
                var plaintextLength = Scalar64(Field(encoded, 10));
                var ciphertextLength = Scalar64(Field(encoded,11));
                if (artifactCount is < 1 or > 195 || plaintextLength != ciphertextLength ||
                    ciphertextLength > 33554432 || ciphertextLength != (ulong)Field(encoded,16).Length)
                    Invalid("The DRC1 ciphertext length is malformed.");
                break;
            }
            case "DPC1":
                ValidateAddress(Field(encoded,9)[0], Field(encoded,10));
                break;
            case "DXR1":
            {
                var phase = Field(encoded, 1)[0];
                Range(phase, 0, 2, "DXR1 phase");
                Range(Field(encoded, 2)[0], 1, 2, "DXR1 role");
                Nonzero(Field(encoded, 3), "DXR1 network");
                Nonzero(Field(encoded, 4), "DXR1 operation ID");
                Nonzero(Field(encoded, 5), "DXR1 subject projection hash");
                Nonzero(Field(encoded, 6), "DXR1 holder X25519 key");
                Nonzero(Field(encoded, 7), "DXR1 issuer ephemeral key");
                Nonzero(Field(encoded, 8), "DXR1 nonce");
                Nonzero(Field(encoded, 9), "DXR1 nonce ledger key");
                Nonzero(Field(encoded, 15), "DXR1 source fingerprint");
                Nonzero(Field(encoded, 16), "DXR1 protected-state key ID");
                Boolean(Field(encoded, 17), "DXR1 fork latch");
                var issued = Scalar64(Field(encoded, 10));
                var expires = Scalar64(Field(encoded, 11));
                var verified = Scalar64(Field(encoded, 12));
                var retained = Scalar64(Field(encoded, 18));
                if (issued >= expires || retained < expires)
                    Invalid("The DXR1 time window is invalid.");
                if (phase == 1)
                {
                    if (verified < issued || verified >= expires ||
                        CanonicalGrammar.IsZero(Field(encoded, 13)) ||
                        CanonicalGrammar.IsZero(Field(encoded, 14)))
                        Invalid("A Verified DXR1 has an invalid verified shape.");
                }
                else if (verified != 0 || !CanonicalGrammar.IsZero(Field(encoded, 13)) ||
                         !CanonicalGrammar.IsZero(Field(encoded, 14)))
                    Invalid("A Pending or Aborted DXR1 has nonzero verified fields.");
                break;
            }
            case "RIP2":
                if (Field(encoded,13)[0] > 12 || Field(encoded,14).Length != Field(encoded,13)[0] * 32)
                    Invalid("The RIP2 sibling table is malformed.");
                break;
            case "MRLC":
                if (Scalar64(Field(encoded,24)) != (ulong)Field(encoded,26).Length ||
                    BinaryPrimitives.ReadUInt32BigEndian(Field(encoded,23)) is < 8 or > 16389)
                    Invalid("The MRLC catalog framing is malformed.");
                break;
        }
        ValidateClosedScalars(encoded, definition.Magic);
    }

    private static void ValidateClosedScalars(ReadOnlySpan<byte> encoded, string magic)
    {
        switch (magic)
        {
            case "DPA1":
                Exact16(Field(encoded, 12), 1, "DPA1 suite");
                break;
            case "DPD1":
                Exact64(Field(encoded, 18), 1, "DPD1 capabilities");
                Exact16(Field(encoded, 19), 1, "DPD1 suite");
                break;
            case "DPM1":
                Mask64(Field(encoded, 16), 3, true, "DPM1 capabilities");
                break;
            case "DRS1":
                ValidateDrsEntries(Field(encoded, 10));
                break;
            case "DRT1":
                Range(Field(encoded, 2)[0], 1, 3, "DRT1 target kind");
                break;
            case "KRT1":
                Range(Field(encoded, 2)[0], 1, 4, "KRT1 key scope");
                Range(Field(encoded, 10)[0], 1, 1, "KRT1 action");
                break;
            case "KRF1":
                Range(Field(encoded, 2)[0], 1, 4, "KRF1 key scope");
                Range(Field(encoded, 9)[0], 2, 2, "KRF1 action");
                break;
            case "DRA1":
                Range(BinaryPrimitives.ReadUInt16BigEndian(Field(encoded, 15)), 1, 3, "DRA1 reason");
                break;
            case "DWD1":
                Exact64(Field(encoded, 10), 15, "DWD1 component mask");
                ValidateWitnessDescriptors(Field(encoded, 14));
                break;
            case "DCP1":
                Range(BinaryPrimitives.ReadUInt16BigEndian(Field(encoded, 3)), 1, 4, "DCP1 component kind");
                break;
            case "DCS1":
                ValidateComponentRows(Field(encoded, 11));
                break;
            case "DCN1":
                Boolean(Field(encoded, 12), "DCN1 terminal state");
                Range(Field(encoded, 26)[0], 1, 1, "DCN1 durability class");
                break;
            case "DHL1":
                Boolean(Field(encoded, 11), "DHL1 terminal state");
                break;
            case "DWL1":
                Boolean(Field(encoded, 12), "DWL1 fork latch");
                Zero(Field(encoded, 13), "DWL1 reserved");
                break;
            case "DPL1":
                Range(BinaryPrimitives.ReadUInt16BigEndian(Field(encoded, 2)), 1, 4, "DPL1 component kind");
                Boolean(Field(encoded, 16), "DPL1 fork latch");
                Zero(Field(encoded, 17), "DPL1 reserved");
                break;
            case "DBG1":
                Range(BinaryPrimitives.ReadUInt16BigEndian(Field(encoded, 2)), 1, 4, "DBG1 component kind");
                break;
            case "DNR1":
                Mask64(Field(encoded, 14), 7, true, "DNR1 roles");
                Mask64(Field(encoded, 15), 31, true, "DNR1 capabilities");
                break;
            case "MRL2":
                Mask64(Field(encoded, 6), 7, true, "MRL2 roles");
                Mask64(Field(encoded, 7), 31, true, "MRL2 capabilities");
                ReferenceShape(Field(encoded, 5), ArtifactType.Dnr1, 756, false,
                    "MRL2 DNR1");
                ReferenceShapeRange(Field(encoded, 9), ArtifactType.Dpc1, 430, 680,
                    "MRL2 anchor DPC1");
                break;
            case "RIP2":
                Exact16(Field(encoded, 5), 2, "RIP2 protocol version");
                ValidateRip2Counts(encoded);
                break;
            case "DPC1":
                Mask64(Field(encoded, 8), 31, true, "DPC1 capabilities");
                Mask64(Field(encoded, 14), 1, false, "DPC1 flags");
                if (BinaryPrimitives.ReadUInt16BigEndian(Field(encoded, 11)) == 0)
                    Invalid("DPC1 port is zero.");
                break;
            case "DPR1":
                Exact16(Field(encoded, 9), 1, "DPR1 operation");
                break;
            case "DPJ1":
                Exact16(Field(encoded, 8), 1, "DPJ1 operation");
                Range(Field(encoded, 11)[0], 0, 2, "DPJ1 phase");
                Boolean(Field(encoded, 12), "DPJ1 delivery latch");
                Boolean(Field(encoded, 13), "DPJ1 stale latch");
                Boolean(Field(encoded, 19), "DPJ1 fork latch");
                Zero(Field(encoded, 20), "DPJ1 reserved");
                ValidateJournalShape(encoded);
                break;
            case "RRM1":
                if (Scalar64(Field(encoded, 2)) != 0 || Scalar64(Field(encoded, 4)) != 0)
                    Invalid("RRM1 generations must be zero in Wave 1.");
                Exact64(Field(encoded, 7), 15, "RRM1 component mask");
                Nonzero(Field(encoded, 3), "RRM1 environment reset ID");
                Nonzero(Field(encoded, 5), "RRM1 release root key");
                Nonzero(Field(encoded, 8), "RRM1 schema fingerprint");
                Nonzero(Field(encoded, 9), "RRM1 signer key ID");
                break;
            case "RRL1":
                Boolean(Field(encoded, 7), "RRL1 terminal state");
                Boolean(Field(encoded, 8), "RRL1 fork latch");
                if (BinaryPrimitives.ReadUInt16BigEndian(Field(encoded, 12)) > 64)
                    Invalid("RRL1 chain entry count exceeds the bound.");
                ValidateReleaseRootLkgShape(encoded);
                break;
            case "DWT1":
                Range(Field(encoded, 8)[0], 3, 3, "DWT1 receipt count");
                ValidateTerminalWitnessRows(Field(encoded, 9));
                ReferenceShape(Field(encoded, 2), ArtifactType.Dwd1, 1217, false, "DWT1 prior DWD1");
                var rootGeneration = Scalar64(Field(encoded, 4));
                ReferenceShape(Field(encoded, 5), rootGeneration == 0 ? ArtifactType.Rrm1 : ArtifactType.Krt1,
                    rootGeneration == 0 ? 332u : 412u, false, "DWT1 root transition");
                ReferenceShape(Field(encoded, 6), ArtifactType.Krf1, 300, false, "DWT1 KRF1");
                break;
        }
    }

    private static void ValidateDrsEntries(ReadOnlySpan<byte> entries)
    {
        if (entries.Length == 62 * 1024 && entries[^62] != 3)
            Invalid("The final DRS1 capacity slot is reserved for AccountTerminal.");
        var terminal = false;
        for (var offset = 0; offset < entries.Length; offset += 62)
        {
            if (terminal) Invalid("A DRS1 terminal entry has a successor.");
            var kind = entries[offset];
            Range(kind, 1, 3, "DRS1 target kind");
            var reference = entries.Slice(offset + 1, 38);
            if (BinaryPrimitives.ReadUInt16BigEndian(reference) != (ushort)ArtifactType.Drt1 ||
                BinaryPrimitives.ReadUInt32BigEndian(reference[2..]) != 179 ||
                CanonicalGrammar.IsZero(reference[6..]))
                Invalid("A DRS1 entry has an invalid DRT1 reference.");
            var reason = BinaryPrimitives.ReadUInt16BigEndian(entries.Slice(offset + 55, 2));
            Range(reason, 1, 4, "DRS1 reason");
            if ((kind == 3) != (reason == 4)) Invalid("A DRS1 terminal reason is mismatched.");
            Zero(entries.Slice(offset + 57, 5), "DRS1 reserved");
            terminal = kind == 3;
        }
    }

    private static void ValidateWitnessDescriptors(ReadOnlySpan<byte> descriptors)
    {
        for (var offset = 0; offset < descriptors.Length; offset += 116)
        {
            var kind = descriptors[offset + 64];
            Range(kind, 1, 2, "witness endpoint kind");
            if (descriptors[offset + 65] != 0) Invalid("A witness descriptor reserved byte is nonzero.");
            if (kind == 1 && descriptors.Slice(offset + 70, 12).IndexOfAnyExcept((byte)0) >= 0)
                Invalid("A witness IPv4 address has a nonzero tail.");
            if (BinaryPrimitives.ReadUInt16BigEndian(descriptors.Slice(offset + 82, 2)) == 0)
                Invalid("A witness port is zero.");
        }
    }

    private static void ValidateComponentRows(ReadOnlySpan<byte> rows)
    {
        for (var index = 0; index < 4; index++)
            if (BinaryPrimitives.ReadUInt16BigEndian(rows.Slice(index * 104, 2)) != index + 1)
                Invalid("DCS1 component rows are not the exact closed order.");
    }

    private static void ValidateRip2Counts(ReadOnlySpan<byte> encoded)
    {
        var mrl = Field(encoded, 12);
        CanonicalGrammar.Preflight(mrl, Mrl2);
        var members = BinaryPrimitives.ReadUInt32BigEndian(Field(encoded, 7));
        var padded = BinaryPrimitives.ReadUInt32BigEndian(Field(encoded, 8));
        var leaf = BinaryPrimitives.ReadUInt32BigEndian(Field(encoded, 9));
        var siblings = Field(encoded, 13)[0];
        if (BinaryPrimitives.ReadUInt16BigEndian(Field(encoded, 5)) != 2 ||
            !Field(encoded, 6).SequenceEqual(Field(mrl, 3)) ||
            members is < 1 or > 4096 || leaf >= members ||
            padded > 4096 || padded != System.Numerics.BitOperations.RoundUpToPowerOf2(members) ||
            siblings != System.Numerics.BitOperations.Log2(padded) ||
            BinaryPrimitives.ReadUInt32BigEndian(Field(encoded, 11)) != 326)
            Invalid("RIP2 count or embedded-length fields are invalid.");
    }

    private static void ValidateTerminalWitnessRows(ReadOnlySpan<byte> rows)
    {
        ReadOnlySpan<byte> previous = default;
        for (var index = 0; index < 3; index++)
        {
            var row = rows.Slice(index * 145, 145);
            Range(row[72], 1, 1, "DWT1 durability class");
            if (index > 0 && previous.SequenceCompareTo(row[..32]) >= 0)
                Invalid("DWT1 witness rows are not strictly sorted and distinct.");
            previous = row[..32];
        }
    }

    private static void ValidateJournalShape(ReadOnlySpan<byte> encoded)
    {
        var phase = Field(encoded, 11)[0];
        var delivery = Field(encoded, 12)[0] == 1;
        var stale = Field(encoded, 13)[0] == 1;
        if (delivery && stale) Invalid("DPJ1 delivery and stale latches conflict.");
        var outcomeZero = CanonicalGrammar.IsZero(Field(encoded, 15));
        var dpsZero = CanonicalGrammar.IsZero(Field(encoded, 16));
        var mrrZero = CanonicalGrammar.IsZero(Field(encoded, 17));
        if (phase < 2 && (!outcomeZero || !dpsZero || !mrrZero) ||
            phase == 2 && (outcomeZero || dpsZero || mrrZero) ||
            delivery && phase != 2)
            Invalid("DPJ1 phase fields are inconsistent.");
        if (phase == 2)
        {
            ReferenceShape(Field(encoded, 16), ArtifactType.Dps1, 444, false, "DPJ1 DPS1");
            ReferenceShape(Field(encoded, 17), ArtifactType.Mrr2, 296, false, "DPJ1 MRR2");
        }
    }

    private static void ValidateReleaseRootLkgShape(ReadOnlySpan<byte> encoded)
    {
        ReferenceShape(Field(encoded, 2), ArtifactType.Rrm1, 332, false, "RRL1 genesis RRM1");
        Nonzero(Field(encoded, 4), "RRL1 current key");
        var generation = Scalar64(Field(encoded, 3));
        ReferenceShape(Field(encoded, 5), generation == 0 ? ArtifactType.Rrm1 : ArtifactType.Krt1,
            generation == 0 ? 332u : 412u, false, "RRL1 current transition");
        ReferenceShape(Field(encoded, 10), ArtifactType.Dwd1, 1217, false, "RRL1 latest DWD1");
        if (Scalar64(Field(encoded, 11)) == 0) Invalid("RRL1 witness epoch is zero.");
        var terminal = Field(encoded, 7)[0] == 1;
        ReferenceShape(Field(encoded, 6), ArtifactType.Krf1, 300, !terminal, "RRL1 terminal KRF1");
        ReferenceShape(Field(encoded, 14), ArtifactType.Dwt1, 714, !terminal, "RRL1 terminal DWT1");
        Nonzero(Field(encoded, 13), "RRL1 chain checkpoint");
        Nonzero(Field(encoded, 15), "RRL1 protected key ID");
    }

    private static void ReferenceShape(
        ReadOnlySpan<byte> value,
        ArtifactType type,
        uint length,
        bool zero,
        string name)
    {
        if (zero)
        {
            if (!CanonicalGrammar.IsZero(value)) Invalid($"The {name} must be zero.");
            return;
        }
        if (BinaryPrimitives.ReadUInt16BigEndian(value) != (ushort)type ||
            BinaryPrimitives.ReadUInt32BigEndian(value[2..6]) != length ||
            CanonicalGrammar.IsZero(value[6..]))
            Invalid($"The {name} reference is invalid.");
    }

    private static void ReferenceShapeRange(
        ReadOnlySpan<byte> value,
        ArtifactType type,
        uint minimumLength,
        uint maximumLength,
        string name)
    {
        var length = BinaryPrimitives.ReadUInt32BigEndian(value[2..6]);
        if (BinaryPrimitives.ReadUInt16BigEndian(value) != (ushort)type ||
            length < minimumLength || length > maximumLength ||
            CanonicalGrammar.IsZero(value[6..]))
            Invalid($"The {name} reference is invalid.");
    }

    private static void Exact16(ReadOnlySpan<byte> value, ushort expected, string name)
    {
        if (BinaryPrimitives.ReadUInt16BigEndian(value) != expected) Invalid($"The {name} is invalid.");
    }

    private static void Exact64(ReadOnlySpan<byte> value, ulong expected, string name)
    {
        if (Scalar64(value) != expected) Invalid($"The {name} is invalid.");
    }

    private static void Mask64(ReadOnlySpan<byte> value, ulong mask, bool nonzero, string name)
    {
        var scalar = Scalar64(value);
        if ((scalar & ~mask) != 0 || nonzero && scalar == 0) Invalid($"The {name} is invalid.");
    }

    private static void Boolean(ReadOnlySpan<byte> value, string name) => Range(value[0], 0, 1, name);

    private static void Range(ulong value, ulong minimum, ulong maximum, string name)
    {
        if (value < minimum || value > maximum) Invalid($"The {name} is invalid.");
    }

    private static void Zero(ReadOnlySpan<byte> value, string name)
    {
        if (value.IndexOfAnyExcept((byte)0) >= 0) Invalid($"The {name} is nonzero.");
    }

    private static void Nonzero(ReadOnlySpan<byte> value, string name)
    {
        if (CanonicalGrammar.IsZero(value)) Invalid($"The {name} is zero.");
    }

    internal static ReadOnlySpan<byte> Field(ReadOnlySpan<byte> encoded, int oneBasedTag)
    {
        var offset = CanonicalGrammar.HeaderLength;
        for (var tag = 1; tag <= oneBasedTag; tag++)
        {
            var length = checked((int)BinaryPrimitives.ReadUInt32BigEndian(encoded.Slice(offset + 4, 4)));
            offset += CanonicalGrammar.FieldHeaderLength;
            if (tag == oneBasedTag) return encoded.Slice(offset, length);
            offset += length;
        }
        throw new ArgumentOutOfRangeException(nameof(oneBasedTag));
    }

    private static void Proof(byte count, ReadOnlySpan<byte> proof)
    {
        if (count > 32 || proof.Length != checked(count * 32))
            Invalid("A witness proof table is malformed.");
    }

    private static void Receipts(byte count, ReadOnlySpan<byte> blob, int maximumReceipt)
    {
        if (count != 3) Invalid("A quorum requires exactly three receipts.");
        var offset = 0;
        for (var index = 0; index < 3; index++)
        {
            if (blob.Length - offset < 4) Invalid("A receipt prefix is truncated.");
            var length = BinaryPrimitives.ReadUInt32BigEndian(blob.Slice(offset, 4));
            if (length == 0 || length > maximumReceipt || length > int.MaxValue)
                Invalid("A receipt length is invalid.");
            offset = checked(offset + 4 + (int)length);
            if (offset > blob.Length) Invalid("A receipt is truncated.");
        }
        if (offset != blob.Length) Invalid("A receipt blob has trailing bytes.");
    }

    private static ulong Scalar64(ReadOnlySpan<byte> value) => BinaryPrimitives.ReadUInt64BigEndian(value);

    private static void ValidateAddress(byte kind, ReadOnlySpan<byte> address)
    {
        if (kind == 1 && address.Length != 4 || kind == 2 && address.Length != 16)
            Invalid("A fixed IP address length is invalid.");
        if (kind == 3)
        {
            if (address.Length is < 3 or > 253 || !IsAscii(address))
                Invalid("A DNS address is invalid.");
            var name = System.Text.Encoding.ASCII.GetString(address);
            var labels = name.Split('.');
            if (labels.Length < 2 || labels.Any(static label =>
                    label.Length is < 1 or > 63 ||
                    !char.IsAsciiLetterOrDigit(label[0]) ||
                    !char.IsAsciiLetterOrDigit(label[^1]) ||
                    label.Any(static value => !(char.IsAsciiLetterOrDigit(value) || value == '-')) ||
                    label.Any(char.IsUpper)))
                Invalid("A DNS address is noncanonical.");
        }
        else if (kind is not (1 or 2)) Invalid("The DPC1 endpoint kind is invalid.");
    }

    private static void Invalid(string message) =>
        throw new RecordException(RecordError.InvalidField, message);

    private static bool IsAscii(ReadOnlySpan<byte> value)
    {
        foreach (var item in value)
            if (item > 0x7f) return false;
        return true;
    }
}
