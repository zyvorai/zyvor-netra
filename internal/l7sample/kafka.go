// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package l7sample

import "encoding/binary"

// kafkaAPIs maps a request API key to its name (the Kafka protocol's stable
// numbering); a key beyond the table is "Other".
var kafkaAPIs = [...]string{
	0: "Produce", 1: "Fetch", 2: "ListOffsets", 3: "Metadata", 4: "LeaderAndIsr", 5: "StopReplica", 6: "UpdateMetadata",
	7: "ControlledShutdown", 8: "OffsetCommit", 9: "OffsetFetch", 10: "FindCoordinator", 11: "JoinGroup", 12: "Heartbeat",
	13: "LeaveGroup", 14: "SyncGroup", 15: "DescribeGroups", 16: "ListGroups", 17: "SaslHandshake", 18: "ApiVersions",
	19: "CreateTopics", 20: "DeleteTopics", 21: "DeleteRecords", 22: "InitProducerId", 23: "OffsetForLeaderEpoch",
	24: "AddPartitionsToTxn", 25: "AddOffsetsToTxn", 26: "EndTxn", 27: "WriteTxnMarkers", 28: "TxnOffsetCommit",
	29: "DescribeAcls", 30: "CreateAcls", 31: "DeleteAcls", 32: "DescribeConfigs", 33: "AlterConfigs", 34: "AlterReplicaLogDirs",
	35: "DescribeLogDirs", 36: "SaslAuthenticate", 37: "CreatePartitions", 38: "CreateDelegationToken", 39: "RenewDelegationToken",
	40: "ExpireDelegationToken", 41: "DescribeDelegationToken", 42: "DeleteGroups", 43: "ElectLeaders", 44: "IncrementalAlterConfigs",
	45: "AlterPartitionReassignments", 46: "ListPartitionReassignments", 47: "OffsetDelete", 48: "DescribeClientQuotas",
	49: "AlterClientQuotas", 50: "DescribeUserScramCredentials", 51: "AlterUserScramCredentials", 55: "DescribeQuorum",
	56: "AlterPartition", 57: "UpdateFeatures", 58: "Envelope", 60: "DescribeCluster", 61: "DescribeProducers", 65: "DescribeTransactions",
	66: "ListTransactions", 67: "AllocateProducerIds", 68: "ConsumerGroupHeartbeat",
}

// A Kafka request: int32 size, int16 api key, int16 api version, int32
// correlation id, then the client id. Responses carry only the correlation id, so
// which request they answer needs connection state a sample does not have; they
// are not classified.
func parseKafka(toServer bool, d []byte) (Obs, bool) {
	if !toServer || len(d) < 12 {
		return Obs{}, false
	}
	size := binary.BigEndian.Uint32(d[0:4])
	key := int(binary.BigEndian.Uint16(d[4:6]))
	ver := binary.BigEndian.Uint16(d[6:8])
	if size < 8 || size > 100<<20 || key > 80 || ver > 20 {
		return Obs{}, false
	}
	op := "Other"
	if key < len(kafkaAPIs) && kafkaAPIs[key] != "" {
		op = kafkaAPIs[key]
	}
	return Obs{Proto: ProtoKafka, Kind: KindRequest, Op: op}, true
}
