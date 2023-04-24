void Send_via_ZMQ(unsigned char send[], int sendlen)
{
    void *context = zmq_ctx_new ();					            //creates a socket to talk to Bob
    void *requester = zmq_socket (context, ZMQ_REQ);		    //creates requester that sends the messages
   	printf("Connecting to Bob and sending the message...\n");
    zmq_connect (requester, "tcp://localhost:5555");		    //make outgoing connection from socket

    zmq_msg_t msg;
    zmq_msg_init_size(&msg, sendlen);
    memcpy(zmq_msg_data(&msg), send, sendlen);
    zmq_msg_send(&msg, requester, 0);
    zmq_msg_close(&msg);

    zmq_close (requester);						                //closes the requester socket
    zmq_ctx_destroy (context);					                //destroys the context & terminates all 0MQ processes
}

unsigned char *Receive_via_ZMQ(unsigned char receive[], int *receivelen, int limit)
{
    void *context = zmq_ctx_new ();			        	                                 //creates a socket to talk to Alice
    void *responder = zmq_socket (context, ZMQ_REP);                                   	//creates responder that receives the messages
   	int rc = zmq_bind (responder, "tcp://*:5555");	                                	//make outgoing connection from socket
    
    zmq_msg_t msg;
    zmq_msg_init(&msg);
    zmq_msg_recv(&msg, responder, 0);
    int received_length = zmq_msg_size(&msg);
    memcpy(receive, zmq_msg_data(&msg), received_length);
    zmq_msg_close(&msg);

    zmq_close (responder);						            //closes the requester socket
    zmq_ctx_destroy (context);					            //destroys the context & terminates all 0MQ processes

    *receivelen = received_length;
    return receive;
}
