module bitcoin_hash (input logic        clk, reset_n, start,
                     input logic [15:0] message_addr, output_addr,
                    output logic        done, mem_clk, mem_we,
                    output logic [15:0] mem_addr,
                    output logic [31:0] mem_write_data,
                     input logic [31:0] mem_read_data);

parameter num_nonces = 16;

//logic [ 4:0] state;
enum logic [2:0] {IDLE, READ, WAIT, BLOCK, BLOCK2, COMPUTE, COMPUTE2, WRITE} state;
//logic [31:0] hout[num_nonces];
logic [31:0] w[16];							
logic [31:0] W[16][8];
logic [31:0] message[20];
logic [31:0] h0, h1, h2, h3, h4, h5, h6, h7;

// final result
logic [31:0] Hf0[num_nonces], Hf1[num_nonces], Hf2[num_nonces], Hf3[num_nonces], Hf4[num_nonces], Hf5[num_nonces], Hf6[num_nonces], Hf7[num_nonces];		//replace h_out ???

logic [31:0] a, b, c, d, e, f, g, h;						
logic [31:0] A[8], B[8], C[8], D[8], E[8], F[8], G[8], H[8];
logic [ 7:0] i, j, iter;
logic [15:0] offset; // in word address
logic [ 7:0] num_blocks;
logic        cur_we;
logic [15:0] cur_addr;
logic [31:0] cur_write_data;

logic hash2;

parameter int k[64] = '{
    32'h428a2f98,32'h71374491,32'hb5c0fbcf,32'he9b5dba5,32'h3956c25b,32'h59f111f1,32'h923f82a4,32'hab1c5ed5,
    32'hd807aa98,32'h12835b01,32'h243185be,32'h550c7dc3,32'h72be5d74,32'h80deb1fe,32'h9bdc06a7,32'hc19bf174,
    32'he49b69c1,32'hefbe4786,32'h0fc19dc6,32'h240ca1cc,32'h2de92c6f,32'h4a7484aa,32'h5cb0a9dc,32'h76f988da,
    32'h983e5152,32'ha831c66d,32'hb00327c8,32'hbf597fc7,32'hc6e00bf3,32'hd5a79147,32'h06ca6351,32'h14292967,
    32'h27b70a85,32'h2e1b2138,32'h4d2c6dfc,32'h53380d13,32'h650a7354,32'h766a0abb,32'h81c2c92e,32'h92722c85,
    32'ha2bfe8a1,32'ha81a664b,32'hc24b8b70,32'hc76c51a3,32'hd192e819,32'hd6990624,32'hf40e3585,32'h106aa070,
    32'h19a4c116,32'h1e376c08,32'h2748774c,32'h34b0bcb5,32'h391c0cb3,32'h4ed8aa4a,32'h5b9cca4f,32'h682e6ff3,
    32'h748f82ee,32'h78a5636f,32'h84c87814,32'h8cc70208,32'h90befffa,32'ha4506ceb,32'hbef9a3f7,32'hc67178f2
};

// Student to add rest of the code here
integer num_words = 20;	//number of words in the message
assign num_blocks = 8'd2; //number of digital blocks, from discussion slides


// SHA256 hash round
function logic [255:0] sha256_op(input logic [31:0] a, b, c, d, e, f, g, h, w,
								input logic [7:0] t);
    logic [31:0] S1, S0, ch, maj, t1, t2; // internal signals

	S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
	// Student to add remaning code below
	// Refer to SHA256 discussion slides to get logic for this function
	ch = (e & f) ^ ((~e) & g);
	t1 = ch + S1 + h + k[t] + w;
	S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
	maj = (a & b) ^ (a & c) ^ (b & c);
	t2 = maj + S0;
	sha256_op = {t1 + t2, a, b, c, d + t1, e, f, g};

endfunction

// word expansion
function logic [31:0] exp_word;
	logic [31:0] s0, s1;
	s0 = rightrotate(w[1],7)^rightrotate(w[1],18)^(w[1]>>3);
	s1 = rightrotate(w[14],17)^rightrotate(w[14],19)^(w[14]>>10);
	exp_word = w[0] + s0 + w[9] + s1;
endfunction

// word expansion for parallel
function logic [31:0] Exp_word(input int m);
	logic [31:0] s0, s1;
	s0 = rightrotate(W[1][m],7)^rightrotate(W[1][m],18)^(W[1][m]>>3);
	s1 = rightrotate(W[14][m],17)^rightrotate(W[14][m],19)^(W[14][m]>>10);
	Exp_word = W[0][m] + s0 + W[9][m] + s1;
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
		if (start) begin
       // Student to add rest of the code  
			h0 <= 32'h0;
			h1 <= 32'h0;
			h2 <= 32'h0;
			h3 <= 32'h0;
			h4 <= 32'h0;
			h5 <= 32'h0;
			h6 <= 32'h0;
			h7 <= 32'h0;
			for (int m = 0; m < 8; m++) begin
					A[m] <= 32'h0;
					B[m] <= 32'h0;
					C[m] <= 32'h0;
					D[m] <= 32'h0;
					E[m] <= 32'h0;
					F[m] <= 32'h0;
					G[m] <= 32'h0;
					H[m] <= 32'h0;
			end
			for (int m = 0; m < num_nonces; m++) begin
					Hf0[m] <= 32'h0;
					Hf1[m] <= 32'h0;
					Hf2[m] <= 32'h0;
					Hf3[m] <= 32'h0;
					Hf4[m] <= 32'h0;
					Hf5[m] <= 32'h0;
					Hf6[m] <= 32'h0;
					Hf7[m] <= 32'h0;
			end
			iter <= 0;
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
			hash2 <= 0;
			offset <= 0;
			cur_we <= 1'b0;
			cur_addr <= message_addr;
			cur_write_data <= 0;
			state <= WAIT;
		end
		else begin
			state <= IDLE;
		end
   end
	// wait 1 clock cycle
	WAIT: begin
		if(cur_we) begin
			cur_write_data <= Hf0[offset];
			state <= WRITE;
		end else begin
			state <= READ;
		end
	end
	// read data from memory
	READ: begin
		if(offset <= num_words) begin
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
		if(j < num_blocks) begin
			// first initialization
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
				state <= COMPUTE;
				end
			// second initialization
			else begin
				hash2 <= 0;
				for (int m = 0; m < 8; m++) begin
					W[0][m] <= message[16];
					W[1][m] <= message[17];
					W[2][m] <= message[18];
					W[3][m] <= 32'd0 + m + iter;
					W[4][m] <= 32'h80000000;
					W[5][m] <= 32'h00000000;
					W[6][m] <= 32'h00000000;
					W[7][m] <= 32'h00000000;
					W[8][m] <= 32'h00000000;
					W[9][m] <= 32'h00000000;
					W[10][m] <= 32'h00000000;
					W[11][m] <= 32'h00000000;
					W[12][m] <= 32'h00000000;
					W[13][m] <= 32'h00000000;
					W[14][m] <= 32'h00000000;
					W[15][m] <= 32'd640;
					A[m] <= h0;
					B[m] <= h1;
					C[m] <= h2;
					D[m] <= h3;
					E[m] <= h4;
					F[m] <= h5;
					G[m] <= h6;
					H[m] <= h7;
					state <= COMPUTE2;
				end
			end
		end
		// Finished hashing, move to WRITE
		else begin
			state <= WAIT;
			offset <= 0;
			cur_addr <= output_addr;
			cur_we <= 1'b1;
			end
		end
    // For each block compute hash function
    // Go back to BLOCK stage after each block hash computation is completed and if
    // there are still number of message blocks available in memory otherwise
    // move to WRITE stage
	COMPUTE: begin
	// 64 processing rounds steps for 512-bit block
		// first 15 w
		if (i <= 14) begin
			{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[i], i);
			i <= i + 1;
			state <= COMPUTE;
		end
		// w[15:63]
		else if(i <= 63) begin
			{a, b, c, d, e, f, g, h} <= sha256_op(a, b, c, d, e, f, g, h, w[15], i);
			for (int n = 0; n < 15; n++) w[n] <= w[n+1];
			w[15] <= exp_word();
			i <= i + 1;
			state <= COMPUTE;
		end
		// 64 iterations finished
		else begin
			// move to BLOCK2 if this is the second hashing
			if (j > 0) begin
				state <= BLOCK2;
				i <= 0;
			// move to BLOCK if this is the first hashing
			end else begin
				h0 <= h0 + a;
				h1 <= h1 + b;
				h2 <= h2 + c;
				h3 <= h3 + d;
				h4 <= h4 + e;
				h5 <= h5 + f;
				h6 <= h6 + g;
				h7 <= h7 + h;
				state <= BLOCK;
				i <= 0;
				j <= j + 1;
			end
		end
	end
	// Third initialization
	BLOCK2: begin
		hash2 <= 1;
		for (int m = 0; m < 8; m++) begin
			W[0][m] <= h0 + A[m];
			W[1][m] <= h1 + B[m];
			W[2][m] <= h2 + C[m];
			W[3][m] <= h3 + D[m];
			W[4][m] <= h4 + E[m];
			W[5][m] <= h5 + F[m];
			W[6][m] <= h6 + G[m];
			W[7][m] <= h7 + H[m];
			W[8][m] <= 32'h80000000;
			W[9][m] <= 32'h00000000;
			W[10][m] <= 32'h00000000;
			W[11][m] <= 32'h00000000;
			W[12][m] <= 32'h00000000;
			W[13][m] <= 32'h00000000;
			W[14][m] <= 32'h00000000;
			W[15][m] <= 32'd256;
			A[m] <= 32'h6a09e667;
			B[m] <= 32'hbb67ae85;
			C[m] <= 32'h3c6ef372;
			D[m] <= 32'ha54ff53a;
			E[m] <= 32'h510e527f;
			F[m] <= 32'h9b05688c;
			G[m] <= 32'h1f83d9ab;
			H[m] <= 32'h5be0cd19;
		end
		state <= COMPUTE2;
	end
	// Parallel hashing
	COMPUTE2: begin
		// first 15 w
		if (i <= 14) begin
			for (int m = 0; m < 8; m++) begin
				{A[m], B[m], C[m], D[m], E[m], F[m], G[m], H[m]} <= sha256_op(A[m], B[m], C[m], D[m], E[m], F[m], G[m], H[m], W[i][m], i);
			end
			i <= i + 1;
			state <= COMPUTE2;
		end
		// w[15:63]
		else if(i <= 63) begin
			for (int m = 0; m < 8; m++) begin
				{A[m], B[m], C[m], D[m], E[m], F[m], G[m], H[m]} <= sha256_op(A[m], B[m], C[m], D[m], E[m], F[m], G[m], H[m], W[15][m], i);
				for (int n = 0; n < 15; n++) W[n][m] <= W[n+1][m];
				W[15][m] <= Exp_word(m);
			end
			i <= i + 1;
			state <= COMPUTE2;
		// 64 iterations finished
		end else begin
			// move to BLOCK2 if this is the second hashing
			if (hash2 == 0) begin
				state <= BLOCK2;
				i <= 0;
			// move to BLOCK if this is the third hashing
			end else begin
				i <= 0;
				// check if all nonces SHA computations are finished
				if (iter < num_nonces - 8) begin
					iter <= iter + 8;
				end else begin
					j <= j + 1;
				end
				// store the result
				for (int m = 0; m < 8; m++) begin
					Hf0[m + iter] <= 32'h6a09e667 + A[m];
					Hf1[m + iter] <= 32'hbb67ae85 + B[m];
					Hf2[m + iter] <= 32'h3c6ef372 + C[m];
					Hf3[m + iter] <= 32'ha54ff53a + D[m];
					Hf4[m + iter] <= 32'h510e527f + E[m];
					Hf5[m + iter] <= 32'h9b05688c + F[m];
					Hf6[m + iter] <= 32'h1f83d9ab + G[m];
					Hf7[m + iter] <= 32'h5be0cd19 + H[m];
				end
				state <= BLOCK;
			end
		end
	end
    // h0 to h7 each are 32 bit hashes, which makes up total 256 bit value
    // h0 to h7 after compute stage has final computed hash value
    // write back these h0 to h7 to memory starting from output_addr
	WRITE: begin
		if(offset < num_nonces-1) begin
			cur_write_data <= Hf0[offset+1];
			offset <= offset + 1;
			state <= WRITE;
		end
		else begin
			state <= IDLE;
		end
	end
	default: begin
		state <= IDLE;
	end
	endcase
end

// Generate done when SHA256 hash computation has finished and moved to IDLE state
assign done = (state == IDLE);

endmodule

