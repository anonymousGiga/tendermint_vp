# Client
## create_client + (client_id, sequence)
(client_state, consensus_State) = msg_verifier.create_client()
sm_client_State = header_build.build_solomachine_client_state(&client_State, &consensus_state, sequence, pk);
sm_consensus_State = header_build.build_solomachine_consensus_state(&consensus_state, pk);

return (sm_client_state, sm_consensus_State)

## update_client 
(client_state, consensus_State) = msg_verifier.update_client()
look client_id: sequence = sequence_cnt 
(sm_header_temp, sign_bytes) = header_builder.construct_solomachine_header(consensus_State, pk, sequence)
sequence_cnt ++;
raw_signture = canister.sign(sign_bytes);
sm_header = header_builder.build_solomachine_header(sm_header_temp, raw_signature)
return sm_header


## misbehaviour



## upgrade_client
msg_verifier.upgrade_client(msg).is_ok()

look client_id: sequence = sequence_cnt 
sm_client_State = header_build.build_solomachine_client_state(&client_State, &consensus_state, sequence, pk);
sequence_cnt++;
sm_consensus_State = header_build.build_solomachine_consensus_state(&consensus_state, pk);

return (sm_client_state, sm_consensus_State)


# Connection


## conn_open_init
// need do nothing

## conn_open_try
input: msg, conn_id, conn_end, client_id

(tm_client_state, tm_consensus_state, conn_id, conn_end, client_id) = msg_verifier.conn_open_try(msg)
(sm_client_state, sm_consensus_state) = (header_builder.build_solomachine_client_state(tm_client_state), header_builder.build_solomachine_consensus_state(tm_consensus_state))

<!-- step 1 -->
let sequence = self.sequence_cnt;
let (sign_bytes, time) = construct_solomachine_connection_sign_bytes(connection_id, connection_end, sequence).unwrap();
raw_signture = canister.sign(sign_bytes);
self.sequence_cnt ++;
let conn_proof = build_solomachine_connection_proof(raw_signature, time) .unwrap();

<!-- step 2 -->
client_proof = 
if msg_type == types::ConnectionMsgType::OpenTry | types::ConnectionMsgType::OpenAck  {
     let sequence = self.sequence_cnt;
     let (sign_bytes, time) = construct_solomachine_client_state_sign_bytes(...);
     raw_signture = canister.sign(sign_bytes);
     self.sequence_cnt ++;
     let client_proof = build_solomachine_connection_proof(raw_signature, time) .unwrap();
     client_proof
} else {
     let client_proof = None;
     client_proof
}; 

<!-- step 3 -->
if msg_type == types::ConnectionMsgType::OpenTry | types::ConnectionMsgType::OpenAck  {
     let sequence = self.sequence_cnt;
     let (sign_bytes, time) = construct_solomachine_consensus_state_sign_bytes(msg_type, client_id, client_state, sm_consensus_state, sequence).unwrap();
     raw_signture = canister.sign(sign_bytes);
     self.sequence_cnt ++;
     let consensus_state_proof = build_solomachine_consensus_proof(client_state, msg_type, raw_signature, time) .unwrap();
     return consensus_state_proof
} else {
     let consensus_state_proof = None
     return consensus_state_proof
}

## conn_open_ack
input: conn_id, conn_end, client_id, msg


(tm_client_state, tm_consensus_state) = msg_verifier.conn_open_ack(msg)
(sm_client_state, sm_consensus_state) = (header_builder.build_solomachine_client_state(tm_client_state), header_builder.build_solomachine_consensus_state(tm_consensus_state))

<!-- step 1 -->
let sequence = self.sequence_cnt;
let (sign_bytes, time) = construct_solomachine_connection_sign_bytes(connection_id, connection_end, sequence).unwrap();
raw_signture = canister.sign(sign_bytes);
self.sequence_cnt ++;
let conn_proof = build_solomachine_connection_proof(raw_signature, time) .unwrap();

<!-- step 2 -->
client_proof = 
if msg_type == types::ConnectionMsgType::OpenTry | types::ConnectionMsgType::OpenAck  {
     let sequence = self.sequence_cnt;
     let (sign_bytes, time) = construct_solomachine_client_state_sign_bytes(...);
     raw_signture = canister.sign(sign_bytes);
     self.sequence_cnt ++;
     let client_proof = build_solomachine_connection_proof(raw_signature, time) .unwrap();
     client_proof
} else {
     let client_proof = None;
     client_proof
}; 

<!-- step 3 -->
if msg_type == types::ConnectionMsgType::OpenTry | types::ConnectionMsgType::OpenAck  {
     let sequence = self.sequence_cnt;
     let (sign_bytes, time) = construct_solomachine_consensus_state_sign_bytes(msg_type, client_id, client_state, sm_consensus_state, sequence).unwrap();
     raw_signture = canister.sign(sign_bytes);
     self.sequence_cnt ++;
     let consensus_state_proof = build_solomachine_consensus_proof(client_state, msg_type, raw_signature, time) .unwrap();
     return consensus_state_proof
} else {
     let consensus_state_proof = None
     return consensus_state_proof
}


## conn_open_confirm

input: conn_id, conn_end, client_id, msg


(tm_client_state, tm_consensus_state) = msg_verifier.conn_open_ack(msg)
(sm_client_state, sm_consensus_state) = (header_builder.build_solomachine_client_state(tm_client_state), header_builder.build_solomachine_consensus_state(tm_consensus_state))

<!-- step 1 -->
let sequence = self.sequence_cnt;
let (sign_bytes, time) = construct_solomachine_connection_sign_bytes(connection_id, connection_end, sequence).unwrap();
raw_signture = canister.sign(sign_bytes);
self.sequence_cnt ++;
let conn_proof = build_solomachine_connection_proof(raw_signature, time) .unwrap();

client_proof = None
consensus_state_proof = None
(conn_proof, client_proof, consensus_state_proof)


# Channel
## chan_open_init
Need do nothing

## chan_open_try
input: msg, port_id, channel_id, channel_end

let sequence = self.sequence_cnt;
self.sequence_cnt ++;
let (sign_bytes, time) = construct_solomachine_connection_sign_bytes(connection_id, connection_end, sequence).unwrap();
raw_signture = canister.sign(sign_bytes);
let channel_proof = build_solomachine_connection_proof(raw_signature, time) .unwrap();
return channel_proof

## chan_open_ack
input: msg, port_id, channel_id, channel_end

let sequence = self.sequence_cnt;
self.sequence_cnt ++;
let (sign_bytes, time) = construct_solomachine_connection_sign_bytes(connection_id, connection_end, sequence).unwrap();
raw_signture = canister.sign(sign_bytes);
let channel_proof = build_solomachine_connection_proof(raw_signature, time) .unwrap();
return channel_proof

## chan_open_confirm
input: msg, port_id, channel_id, channel_end

let sequence = self.sequence_cnt;
self.sequence_cnt ++;
let (sign_bytes, time) = construct_solomachine_connection_sign_bytes(connection_id, connection_end, sequence).unwrap();
raw_signture = canister.sign(sign_bytes);
let channel_proof = build_solomachine_connection_proof(raw_signature, time) .unwrap();
return channel_proof

## chan_close_init
input: msg, port_id, channel_id, channel_end

let sequence = self.sequence_cnt;
self.sequence_cnt ++;
let (sign_bytes, time) = construct_solomachine_connection_sign_bytes(connection_id, connection_end, sequence).unwrap();
raw_signture = canister.sign(sign_bytes);
let channel_proof = build_solomachine_connection_proof(raw_signature, time) .unwrap();
return channel_proof

## chan_close_confirm

input: msg, port_id, channel_id, channel_end

let sequence = self.sequence_cnt;
self.sequence_cnt ++;
let (sign_bytes, time) = construct_solomachine_connection_sign_bytes(connection_id, connection_end, sequence).unwrap();
raw_signture = canister.sign(sign_bytes);
let channel_proof = build_solomachine_connection_proof(raw_signature, time) .unwrap();
return channel_proof

## acknowledgement

## recv_packet


## send_packet
## timeout_on_close
## timeout
## write_acknowledgement
