#Samuel Jero <sjero@purdue.edu>
#Congestion Control Manipulations
#These numbers are based on a test connection that transfers 10-11k packets

#bytes_per_ack
div_param_full = [
    1000,
    100,
    10,
    1
]
div_param_small = [
    1000,
    1,
]
div_param_template = "bpc={0!s}"


#num_dups
dup_param_full = [
   1,
   2,
   3,
   10,
   100,
]
dup_param_small = [
    2,
    10,
]
dup_param_template = "num={0!s}"


#burst_size
burst_param_full = [
    2,
    4,
    10,
    100,
]
burst_param_small = [
    2,
    10,
]
burst_param_template = "num={0!s}"


#amt_to_opt_ack
preack_param_full = [
#    100,
#    1000,
#    10000,
    100000,
]
preack_param_small = [
#    1000,
    100000,
]
preack_param_template = "method=2&amt={0!s}"


#amt_to_renege
renege_param_full = [
    10,
    100,
    1000,
    5000,
]
renege_param_small = [
    1000,
    100000,
]
renege_param_template = "growth=1&amt={0!s}"


selfish_receiver_actions = [
 [ "DIV", div_param_template, div_param_full, div_param_small],
 [ "DUP", dup_param_template, dup_param_full, dup_param_small],
 [ "BURST", burst_param_template, burst_param_full, burst_param_small],
 [ "PREACK", preack_param_template, preack_param_full, preack_param_small],
 #[ "RENEGE", renege_param_template, renege_param_full, renege_param_small],
]


length_full = [
    50000,
    4000,
    2000,
    1000,
    500,
    100,
    10,
]


start_full = [
    0,
    4,
    100,
    1000,
    5000,
]


chunk_start = [
    0,
    2000,
    4000,
    6000,
]
chunk_len = 2000
