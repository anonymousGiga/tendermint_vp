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
## conn_open_ack


## conn_open_confirm
ibc-rs: verify_connection_state

## conn_open_init
// need do nothing

## conn_open_try

# Channel
## acknowledgement
## chan_close_confirm
## chan_close_init
## chan_open_ack
## chan_open_confirm
## chan_open_init
## chan_open_try
## recv_packet
## send_packet
## timeout_on_close
## timeout
## write_acknowledgement
