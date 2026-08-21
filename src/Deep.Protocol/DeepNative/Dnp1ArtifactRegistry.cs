using System.Collections.ObjectModel;

namespace Deep.Protocol.DeepNative;

internal static class ArtifactRegistry
{
    internal const ushort IdentityAuthV1Ed25519 = 0x0001;
    internal const ushort CommittedUnsigned = 0x0000;
    internal const ushort ProtectedHmacSha256 = 0x8001;
    internal const ushort ProtectedAead = 0x8002;

    private static readonly IReadOnlyDictionary<ArtifactType, string> NewDomains =
        new ReadOnlyDictionary<ArtifactType, string>(new Dictionary<ArtifactType, string>
        {
            [ArtifactType.Dpa1] = "Deep/Artifact/V1/DPA1",
            [ArtifactType.Dpd1] = "Deep/Artifact/V1/DPD1",
            [ArtifactType.Dpm1] = "Deep/Artifact/V1/DPM1",
            [ArtifactType.Drs1] = "Deep/Artifact/V1/DRS1",
            [ArtifactType.Drt1] = "Deep/Artifact/V1/DRT1",
            [ArtifactType.Krt1] = "Deep/Artifact/V1/KRT1",
            [ArtifactType.Krf1] = "Deep/Artifact/V1/KRF1",
            [ArtifactType.Dcm1] = "Deep/Artifact/V1/DCM1",
            [ArtifactType.Dcp1] = "Deep/Artifact/V1/DCP1",
            [ArtifactType.Dra1] = "Deep/Artifact/V1/DRA1",
            [ArtifactType.Dnr1] = "Deep/Artifact/V1/DNR1",
            [ArtifactType.Mrl2] = "Deep/Artifact/V1/MRL2",
            [ArtifactType.Dpc1] = "Deep/Artifact/V1/DPC1",
            [ArtifactType.Dpl1] = "Deep/Artifact/V1/DPL1",
            [ArtifactType.Dbg1] = "Deep/Artifact/V1/DBG1",
            [ArtifactType.Rib1] = "Deep/Artifact/V1/RIB1",
            [ArtifactType.Xib1] = "Deep/Artifact/V1/XIB1",
            [ArtifactType.Mrlc] = "Deep/Artifact/V1/MRLC",
            [ArtifactType.Dwd1] = "Deep/Artifact/V1/DWD1",
            [ArtifactType.Dcs1] = "Deep/Artifact/V1/DCS1",
            [ArtifactType.Dct1] = "Deep/Artifact/V1/DCT1",
            [ArtifactType.Dcn1] = "Deep/Artifact/V1/DCN1",
            [ArtifactType.Dcq1] = "Deep/Artifact/V1/DCQ1",
            [ArtifactType.Dhl1] = "Deep/Artifact/V1/DHL1",
            [ArtifactType.Dcl1] = "Deep/Artifact/V1/DCL1",
            [ArtifactType.Dwl1] = "Deep/Artifact/V1/DWL1",
            [ArtifactType.Drc1] = "Deep/Artifact/V1/DRC1",
            [ArtifactType.Dpr1] = "Deep/Artifact/V1/DPR1",
            [ArtifactType.Dps1] = "Deep/Artifact/V1/DPS1",
            [ArtifactType.Dpj1] = "Deep/Artifact/V1/DPJ1"
            ,[ArtifactType.Rip2] = "Deep/Artifact/V1/RIP2"
            ,[ArtifactType.Rrm1] = "Deep/Artifact/V1/RRM1"
            ,[ArtifactType.Rrl1] = "Deep/Artifact/V1/RRL1"
            ,[ArtifactType.Dwt1] = "Deep/Artifact/V1/DWT1"
        });

    private static readonly IReadOnlySet<ArtifactType> Retained =
        new HashSet<ArtifactType>
        {
            ArtifactType.Msm1, ArtifactType.Prq2, ArtifactType.Mrr2,
            ArtifactType.Pma1, ArtifactType.Pmr1, ArtifactType.DgSource,
            ArtifactType.Mng1, ArtifactType.Mdg1, ArtifactType.Mrv1,
            ArtifactType.Mmc1
        };

    private static readonly IReadOnlyDictionary<string, string> ProtectedDomains =
        new ReadOnlyDictionary<string, string>(new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["DPL1"] = "Deep/ProtectedState/V1/DPL1",
            ["DBG1"] = "Deep/ProtectedState/V1/DDBG1",
            ["RIB1"] = "Deep/ProtectedState/V1/DRIB1",
            ["XIB1"] = "Deep/ProtectedState/V1/DXIB1",
            ["DWL1"] = "Deep/ProtectedState/V1/DWL1",
            ["MRLC"] = "Deep/ProtectedState/V1/MRLC1",
            ["DPJ1"] = "Deep/ProtectedState/V1/DPJ1",
            ["RRL1"] = "Deep/ProtectedState/V1/RRL1",
            ["DXR1"] = "Deep/ProtectedState/V1/DXP1-verified-receipt"
        });

    internal static bool IsKnown(ArtifactType type) =>
        NewDomains.ContainsKey(type) || Retained.Contains(type);

    internal static bool IsRetained(ArtifactType type) => Retained.Contains(type);

    internal static string GetNewArtifactDomain(ArtifactType type) =>
        NewDomains.TryGetValue(type, out var domain)
            ? domain
            : throw new RecordException(
                RecordError.InvalidArtifactReference,
                "The artifact type does not use a Wave 1 artifact domain.");

    internal static string GetProtectedDomain(string magic) =>
        ProtectedDomains.TryGetValue(magic, out var domain)
            ? domain
            : throw new RecordException(
                RecordError.InvalidField,
                "The record does not use the protected-state HMAC construction.");
}
