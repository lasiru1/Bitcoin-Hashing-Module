module simplified_sha256 #(parameter integer NUM_OF_WORDS = 20)(
 input  logic       clk, reset_n, start,
 input  logic[15:0] message_addr, output_addr,
 output logic       done, mem_clk, mem_we,
 output logic[15:0] mem_addr,
 output logic[31:0] mem_write_data,
 input  logic[31:0] mem_read_data);

// FSM state variables 
enum logic [2:0] {IDLE, READ, BLOCK, COMPUTE, WRITE, DELAY} state;

// NOTE : Below mentioned frame work is for reference purpose.
// Local variables might not be complete and you might have to add more variables
// or modify these variables. Code below is more as a reference.

// Local variables
logic[31:0]  w[16];
logic[31:0]  message[20];
logic[31:0]  h0, h1, h2, h3, h4, h5, h6, h7;
logic[31:0]  a, b, c, d, e, f, g, h;
logic[ 7:0]  i, j;
logic[15:0]  offset; // in word address
logic[ 7:0]  num_blocks;
logic        cur_we;
logic[15:0]  cur_addr;
logic[31:0]  cur_write_data;
logic[512:0] memory_block;
logic[ 7:0]  tstep;
logic[31:0]  hash_out[8];

// SHA256 K constants
parameter int k[0:63] = '{
   32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
   32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
   32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
   32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
   32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
   32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
   32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
   32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};

assign num_blocks = determine_num_blocks(NUM_OF_WORDS); 
assign tstep = (i - 1);

// Note : Function defined are for reference purpose. Feel free to add more functions or modify below.
// Function to determine number of blocks in memory to fetch
function logic [15:0] determine_num_blocks(input logic [31:0] size);

  // Student to add function implementation
  // message is processed in 512-bit blocks sequentially:
  determine_num_blocks = (size*32/512) + 1;

endfunction


// SHA256 hash round
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
                                 input logic [7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals
begin
    S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
    // Student to add remaning code below
    // Refer to SHA256 discussion slides to get logic for this function
    ch  = (e & f) ^ ((~e) & g);
    t1  = ch + S1 + h + k[t] + w;
    S0  = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
    maj = (a & b) ^ (a & c) ^ (b & c);
    t2  = maj + S0;
    sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};
end
endfunction

// Compression function includes two steps: Word Expansion followed by SHA256 Operatiion
// Step 1: Word Expansion
function logic [31:0] exp_word;
  logic [31:0] s0, s1;
  s0 = rightrotate(w[1],7)^rightrotate(w[1],18)^(w[1]>>3);
  s1 = rightrotate(w[14],17)^rightrotate(w[14],19)^(w[14]>>10);
  exp_word = w[0] + s0 + w[9] + s1;
endfunction

// Generate request to memory
// for reading from memory to get original message
// for writing final computed has value
assign mem_clk = clk;
assign mem_addr = cur_addr + offset;
assign mem_we = cur_we;
assign mem_write_data = cur_write_data;

// Right Rotation Example : right rotate input x by r
// Lets say input x = 1111 ffff 2222 3333 4444 6666 7777 8888
// lets say r = 4
// x >> r  will result in : 0000 1111 ffff 2222 3333 4444 6666 7777 
// x << (32-r) will result in : 8888 0000 0000 0000 0000 0000 0000 0000
// final right rotate expression is = (x >> r) | (x << (32-r));
// (0000 1111 ffff 2222 3333 4444 6666 7777) | (8888 0000 0000 0000 0000 0000 0000 0000)
// final value after right rotate = 8888 1111 ffff 2222 3333 4444 6666 7777
// Right rotation function
function logic [31:0] rightrotate(input logic [31:0] x,
                                  input logic [ 7:0] r);
   rightrotate = (x >> r) | (x << (32 - r));
endfunction

// SHA-256 FSM 
// Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function
// and write back hash value back to memory
always_ff @(posedge clk, negedge reset_n)
begin
  if (!reset_n) begin
    cur_we <= 1'b0;
    state <= IDLE;
  end 
  else case (state)
    // Initialize hash values h0 to h7 and a to h, other variables and memory we, address offset, etc
    IDLE: begin 
      if(start) begin
        // Student to add rest of the code  
        h0 <= 32'h0;
        h1 <= 32'h0;
        h2 <= 32'h0;
        h3 <= 32'h0;
        h4 <= 32'h0;
        h5 <= 32'h0;
        h6 <= 32'h0;
        h7 <= 32'h0;
        a <= 32'h0;
        b <= 32'h0;
        c <= 32'h0;
        d <= 32'h0;
        e <= 32'h0;
        f <= 32'h0;
        g <= 32'h0;
        h <= 32'h0;
        i <= 0;
        j <= 0; 
        offset <= 0;
        cur_we <= 1'b0;
        cur_addr <= message_addr;
        cur_write_data <= 0;
        state <= DELAY;
      end
      else begin
        state <= IDLE;
      end 
    end

    // issue a new read/write command
    // data needs to be available on mem_read_data for a read command
    DELAY: begin
      if(cur_we) begin
        cur_write_data <= hash_out[offset];
        state <= WRITE;
      end
      else begin
        state <= READ;
      end
    end

    // Memory Model:
    // at next clock cycle, read data from mem_read_data
    READ: begin
      if(offset <= NUM_OF_WORDS) begin
        message[offset-1] <= mem_read_data;
        offset <= offset + 1;
        state <= READ;
      end
      else begin
        state <= BLOCK;
      end
    end

    // SHA-256 FSM 
    // Get a BLOCK from the memory, COMPUTE Hash output using SHA256 function    
    // and write back hash value back to memory
    BLOCK: begin
      // Fetch message in 512-bit block size
      // For each of 512-bit block initiate hash value computation

      // determine if num_blocks is less than 2:
      if(j < num_blocks) begin
        state <= COMPUTE;

        // first message block has first 16 words of input message stored in 'w' array
        if(j == 0) begin
          h0 <= 32'h6a09e667;
          h1 <= 32'hbb67ae85;
          h2 <= 32'h3c6ef372;
          h3 <= 32'ha54ff53a;
          h4 <= 32'h510e527f;
          h5 <= 32'h9b05688c;
          h6 <= 32'h1f83d9ab;
          h7 <= 32'h5be0cd19;
          a <= 32'h6a09e667;
          b <= 32'hbb67ae85;
          c <= 32'h3c6ef372;
          d <= 32'ha54ff53a;
          e <= 32'h510e527f;
          f <= 32'h9b05688c;
          g <= 32'h1f83d9ab;
          h <= 32'h5be0cd19;
          w <= message[0:15];
        end

        // second message block has 4 words of input message, value 1, padding 0, and message size 640
        else begin 
          w[0:3] <= message[16:19];
          w[4] <= 32'h80000000;
          for (int x = 5; x <= 14; x++) begin
            w[x] <= 32'h00000000;
          end

          // set message size 640
          w[15] = 32'd640;
          a <= h0;
          b <= h1;
          c <= h2;
          d <= h3;
          e <= h4;
          f <= h5;
          g <= h6;
          h <= h7;
        end
      end

      // both blocks SHA256 operation has been processed and hash is created.
      // moving to WRITE state
      else begin
        state <= DELAY;
        hash_out[0] <= h0;
        hash_out[1] <= h1;
        hash_out[2] <= h2;
        hash_out[3] <= h3;
        hash_out[4] <= h4;
        hash_out[5] <= h5;
        hash_out[6] <= h6;
        hash_out[7] <= h7;
        offset <= 0;
        cur_we <= 1'b1;
        cur_addr <= output_addr;
      end
    end

    // For each block compute hash function
    // Go back to BLOCK stage after each block hash computation is completed and if
    // there are still number of message blocks available in memory otherwise
    // move to WRITE stage
    COMPUTE: begin
      // 64 processing rounds steps for 512-bit block 

      // process first message block (first set of words)
      if(i <= 14) begin
        {a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[i], i);
        i <= i + 1;
        state <= COMPUTE;
      end

      // process second message block (second set of words)
      else if(i <= 63) begin
        {a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[15], i);
        i <= i + 1;
        state <= COMPUTE;

        // perform word expansion of input message block (512 bits)
        for(int z = 0; z < 15; z++) begin
          w[z] <= w[z+1];
        end
        w[15] <= exp_word();
      end

      // hash values for 'a' through 'h' have been generated
      // adding previous hash values with 'a' through 'h' hash values
      else begin
        h0 <= h0 + a;
        h1 <= h1 + b;
        h2 <= h2 + c;
        h3 <= h3 + d;
        h4 <= h4 + e;
        h5 <= h5 + f;
        h6 <= h6 + g;
        h7 <= h7 + h;

        // go badk to BLOCK state
        state <= BLOCK;
        i <= 0;

        // increment number of blocks iteration variable
        j <= j + 1;
      end
    end

    // h0 to h7 each are 32 bit hashes, which makes up total 256 bit value
    // h0 to h7 after compute stage has final computed hash value
    // write back these h0 to h7 to memory starting from output_addr
    WRITE: begin
      if(offset < 7) begin

        // write 256-bit hash value stored in h0 to h7 hash variables in testbench memory
        cur_write_data <= hash_out[offset+1];
        offset <= offset + 1;
        state <= WRITE;
      end
      else begin
        state <= IDLE;
      end
    end

    // default case: SHA256 FSM will remain in IDLE in iput is invalid
    default: begin
      $display("Invalid state! SHA256 FSM remains in IDLE.");
      state <= IDLE;
    end

  endcase
end

// Generate done when SHA256 hash computation has finished and moved to IDLE state
assign done = (state == IDLE);

endmodule: simplified_sha256

