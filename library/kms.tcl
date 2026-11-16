# 
# Copyright Jerily LTD. All Rights Reserved.
# SPDX-FileCopyrightText: 2026 Neofytos Dimitriou (neo@jerily.cy)
# SPDX-License-Identifier: MIT.
# 

package require pure-tcl-aws-core 0.1.0
namespace eval ::aws::kms {namespace path ::aws::core}
::aws::core::register kms {list_keys create_key describe_key enable_key disable_key schedule_key_deletion cancel_key_deletion encrypt decrypt generate_data_key generate_random}

# Dispatch a KMS JSON operation.
proc ::aws::kms::call {client action fields {retry 0}} {json $client TrentService.$action $fields 1.1 $retry}

# Follow every page of key ARNs.
proc ::aws::kms::_list_keys {client} {
    set fields [dict create Limit {N 1000}]; set out {}; set seen {}
    while {1} {
        set page [call $client ListKeys $fields 1]
        foreach key [get $page Keys] {lappend out [dict get $key KeyArn]}
        if {![get $page Truncated 0]} {return $out}
        set marker [required $page NextMarker]; next seen $marker
        dict set fields Marker [list S $marker]
    }
}

# Create a default symmetric encryption key and return its ARN.
proc ::aws::kms::_create_key {client} {dict get [call $client CreateKey {}] KeyMetadata Arn}

# Return KMS key metadata without changing AWS field names.
proc ::aws::kms::_describe_key {client arn} {dict get [call $client DescribeKey [dict create KeyId [list S $arn]] 1] KeyMetadata}

# Enable the key and return its identifier.
proc ::aws::kms::_enable_key {client arn} {call $client EnableKey [dict create KeyId [list S $arn]] 1; return $arn}

# Disable the key and return its identifier.
proc ::aws::kms::_disable_key {client arn} {call $client DisableKey [dict create KeyId [list S $arn]] 1; return $arn}

# Schedule key deletion and return its Unix timestamp.
proc ::aws::kms::_schedule_key_deletion {client arn {days 30}} {
    integer $days 7 30 pending_window_in_days
    set result [call $client ScheduleKeyDeletion [dict create KeyId [list S $arn] PendingWindowInDays [list N $days]]]
    return [expr {wide([dict get $result DeletionDate])}]
}

# Cancel pending deletion and return the key identifier.
proc ::aws::kms::_cancel_key_deletion {client arn} {call $client CancelKeyDeletion [dict create KeyId [list S $arn]]; return $arn}

# Encrypt raw bytes and return the binary ciphertext blob.
proc ::aws::kms::_encrypt {client arn bytes} {
    binary decode base64 [dict get [call $client Encrypt [dict create KeyId [list S $arn] Plaintext [list S [binary encode base64 -maxlen 0 $bytes]]]] CiphertextBlob]
}

# Decrypt a ciphertext blob and return raw plaintext bytes.
proc ::aws::kms::_decrypt {client bytes} {
    binary decode base64 [dict get [call $client Decrypt [dict create CiphertextBlob [list S [binary encode base64 -maxlen 0 $bytes]]] 1] Plaintext]
}

# Return the plaintext and encrypted data keys as a two-element list.
proc ::aws::kms::_generate_data_key {client arn size} {
    integer $size 1 1024 number_of_bytes
    set r [call $client GenerateDataKey [dict create KeyId [list S $arn] NumberOfBytes [list N $size]]]
    list [binary decode base64 [dict get $r Plaintext]] [binary decode base64 [dict get $r CiphertextBlob]]
}

# Request cryptographically random bytes from KMS.
proc ::aws::kms::_generate_random {client size} {
    integer $size 1 1024 number_of_bytes
    binary decode base64 [dict get [call $client GenerateRandom [dict create NumberOfBytes [list N $size]]] Plaintext]
}
package provide pure-tcl-aws-kms 0.1.0
package provide awskms 1.0.19
