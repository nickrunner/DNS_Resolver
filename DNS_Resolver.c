

int main(){

/*take user input for port number */

/*wait for client connection*/

/*request was found, check if is type A and class IN*/

/*if request is type A, class IN*/
  //unset recursion desired bit
  
  /*while the query has not been resolved */
    //forward the request to a root name server(see link in proj discription)
    
    /*wait for response from root name server*/
    //if REPLY is received
      //if RCODE has errors
        //send message to client that there were errors, finish query    
      //else (RCODE has no errors)
        //if: an answer was obtained
          //send message to client with the answer
        //else: 
          //read the NS record 2 bytes, this tells of next server to ask
          //forward the same query to this server 

/*if not typeA class IN*/
  //respond to the client with the appropriate RCODE notifying the client
  // that this type of query is not supported
  



}
