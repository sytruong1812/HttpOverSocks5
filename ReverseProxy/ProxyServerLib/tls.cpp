#include "tls.h"
#include "utils.h"

namespace NetworkOperations
{
	CredHandle SchannelTLS::get_schannel_client_handle(PCCERT_CONTEXT cert_ctx)
	{
		// Initialize a credentials handle for Secure Channel.
		SCHANNEL_CRED cred_data = { 0 };
		cred_data.dwVersion = SCHANNEL_CRED_VERSION;
		cred_data.dwFlags = SCH_USE_STRONG_CRYPTO	// Disable deprecated or otherwise weak algorithms (on as default).
			| SCH_CRED_NO_DEFAULT_CREDS				// Client certs are not supported.
			| SCH_CRED_MANUAL_CRED_VALIDATION;		// Disable Schannel's automatic server cert validation; the app must validate manually.
		// Enable automatically validate server cert (on as default) = SCH_CRED_AUTO_CRED_VALIDATION.	
		if (cert_ctx)
		{
			cred_data.cCreds = 1;
			cred_data.paCred = &cert_ctx;
		}
		OSVERSIONINFOEXW osvi;
		SecureZeroMemory(&osvi, sizeof(OSVERSIONINFOEXW));
		osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
		typedef LONG(__stdcall* RtlGetVersion)(LPOSVERSIONINFOEXW);
		if (const HMODULE ntdll = GetModuleHandleW(L"ntdll"))
		{
			if (const RtlGetVersion pRtlGetVersion = (RtlGetVersion)GetProcAddress(ntdll, "RtlGetVersion"))
			{
				if (pRtlGetVersion(&osvi) == 0)
				{
					if (osvi.dwMajorVersion <= 6)
					{
						if (osvi.dwMinorVersion < 2)
						{
							// WIN 7
							cred_data.grbitEnabledProtocols = SP_PROT_TLS1_0_CLIENT;
						}
						else
						{
							// WIN 8, WIN 8.1
							cred_data.grbitEnabledProtocols = SP_PROT_TLS1_1_CLIENT | SP_PROT_TLS1_2_CLIENT;
						}
					}
					else
					{
						// WIN 10, WIN 11
						cred_data.grbitEnabledProtocols = SP_PROT_TLS1_1_CLIENT | SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT;
					}
				}
			}
		}

		CredHandle cred_handle;
		SECURITY_STATUS sec_status = AcquireCredentialsHandleA(
			NULL,				   // default principal
			(LPSTR)UNISP_NAME_A,   // name of the SSP
			SECPKG_CRED_OUTBOUND,  // client will use the credentials
			NULL,                  // use the current LOGON id
			&cred_data,            // protocol-specific data
			NULL,                  // default
			NULL,                  // default
			&cred_handle,		   // receives the credential handle
			NULL);				   // receives the credential time limit
		if (sec_status != SEC_E_OK)
		{
			LOG_ERROR_A("[SchannelTLS] AcquireCredentialsHandleW() returned error = %ld", sec_status);
			free_cred_handle(cred_handle);
		}
		return cred_handle;
	}

	CredHandle SchannelTLS::get_schannel_server_handle(PCCERT_CONTEXT cert_ctx)
	{
		// Initialize a credentials handle for Secure Channel.
		SCHANNEL_CRED cred_data = { 0 };
		cred_data.dwVersion = SCHANNEL_CRED_VERSION;
		cred_data.dwFlags = SCH_USE_STRONG_CRYPTO	// Disable deprecated or otherwise weak algorithms (on as default).
			| SCH_CRED_NO_DEFAULT_CREDS				// Client certs are not supported.
			| SCH_CRED_MANUAL_CRED_VALIDATION;		// Disable Schannel's automatic server cert validation; the app must validate manually.
		// Enable automatically validate server cert (on as default) = SCH_CRED_AUTO_CRED_VALIDATION.	
		if (cert_ctx)
		{
			cred_data.cCreds = 1;
			cred_data.paCred = &cert_ctx;
		}
		OSVERSIONINFOEXW osvi;
		SecureZeroMemory(&osvi, sizeof(OSVERSIONINFOEXW));
		osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
		typedef LONG(__stdcall* RtlGetVersion)(LPOSVERSIONINFOEXW);
		if (const HMODULE ntdll = GetModuleHandleW(L"ntdll"))
		{
			if (const RtlGetVersion pRtlGetVersion = (RtlGetVersion)GetProcAddress(ntdll, "RtlGetVersion"))
			{
				if (pRtlGetVersion(&osvi) == 0)
				{
					if (osvi.dwMajorVersion <= 6)
					{
						if (osvi.dwMinorVersion < 2)
						{
							// WIN 7
							cred_data.grbitEnabledProtocols = SP_PROT_TLS1_0_CLIENT;
						}
						else
						{
							// WIN 8, WIN 8.1
							cred_data.grbitEnabledProtocols = SP_PROT_TLS1_1_CLIENT | SP_PROT_TLS1_2_CLIENT;
						}
					}
					else
					{
						// WIN 10, WIN 11
						cred_data.grbitEnabledProtocols = SP_PROT_TLS1_1_CLIENT | SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT;
					}
				}
			}
		}

		CredHandle cred_handle;
		SECURITY_STATUS sec_status = AcquireCredentialsHandleA(
			NULL,				   // default principal
			(LPSTR)UNISP_NAME_A,   // name of the SSP
			SECPKG_CRED_INBOUND,   // client will use the credentials
			NULL,                  // use the current LOGON id
			&cred_data,            // protocol-specific data
			NULL,                  // default
			NULL,                  // default
			&cred_handle,		   // receives the credential handle
			NULL);				   // receives the credential time limit
		if (sec_status != SEC_E_OK)
		{
			LOG_ERROR_A("[SchannelTLS] AcquireCredentialsHandleW() returned error = %ld", sec_status);
			free_cred_handle(cred_handle);
		}
		return cred_handle;
	}

	void SchannelTLS::free_cred_handle(CredHandle cred_handle)
	{
		if (SecIsValidHandle(&cred_handle))
		{
			FreeCredentialsHandle(&cred_handle);
		}
	}

	void SchannelTLS::free_ctxt_handle(CtxtHandle ctxt_handle)
	{
		if (SecIsValidHandle(&ctxt_handle))
		{
			DeleteSecurityContext(&ctxt_handle);
		}
	}



	CtxtHandle SchannelTLS::server_perform_handshake(CredHandle cred_handle, PWSocket transport)
	{
		// Input buffer
		auto buffer_in = std::make_unique<char[]>(TLS_MAX_RECORD_SIZE);

		SecBuffer secure_buffer_in[2] = { 0 };
		init_sec_buffer(secure_buffer_in[0], SECBUFFER_TOKEN, TLS_MAX_RECORD_SIZE, buffer_in.get());
		init_sec_buffer(secure_buffer_in[1], SECBUFFER_EMPTY, 0, nullptr);

		SecBufferDesc secure_buffer_desc_in = { 0 };
		init_sec_buffer_desc(secure_buffer_desc_in, SECBUFFER_VERSION, 2, secure_buffer_in);

		// Output buffer
		SecBuffer secure_buffer_out[3] = { 0 };
		init_sec_buffer(secure_buffer_out[0], SECBUFFER_TOKEN, 0, nullptr);
		init_sec_buffer(secure_buffer_out[1], SECBUFFER_ALERT, 0, nullptr);
		init_sec_buffer(secure_buffer_out[2], SECBUFFER_EMPTY, 0, nullptr);

		SecBufferDesc secure_buffer_desc_out = { 0 };
		init_sec_buffer_desc(secure_buffer_desc_out, SECBUFFER_VERSION, 3, secure_buffer_out);
		Helper::DeferFunctionRAII free_buffers_deferred([&secure_buffer_desc_out]() { free_all_buffers(secure_buffer_desc_out); });

		CtxtHandle ctxt_handle = { 0 };
		bool first_iteration = true;
		bool authn_completed = false;
		while (!authn_completed)
		{
			secure_buffer_in[0].cbBuffer = transport->tcp_recv_data((char*)secure_buffer_in[0].pvBuffer, TLS_MAX_RECORD_SIZE);

			SECURITY_STATUS sec_status = AcceptSecurityContext(
											&cred_handle,
											first_iteration ? NULL : &ctxt_handle,
											&secure_buffer_desc_in,
											ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_CONFIDENTIALITY,
											0,
											&ctxt_handle,
											&secure_buffer_desc_out,
											NULL,
											NULL);
			first_iteration = false;

			switch (sec_status)
			{
			case SEC_E_OK:
			case SEC_I_CONTINUE_NEEDED:
			{
				if (secure_buffer_out[0].cbBuffer > 0)
				{
					transport->tcp_send_data((const char*)secure_buffer_out[0].pvBuffer, secure_buffer_out[0].cbBuffer);
				}
				if (sec_status == SEC_E_OK)
				{
					authn_completed = true;
				}
				break;
			}
			case SEC_I_COMPLETE_AND_CONTINUE:
			case SEC_I_COMPLETE_NEEDED:
			{
				SECURITY_STATUS complete_sec_status = SEC_E_OK;
				complete_sec_status = CompleteAuthToken(&ctxt_handle, &secure_buffer_desc_out);
				if (complete_sec_status == SEC_E_OK)
				{
					if (secure_buffer_out[0].cbBuffer > 0)
					{
						transport->tcp_send_data((const char*)secure_buffer_out[0].pvBuffer, secure_buffer_out[0].cbBuffer);
					}
				}
				if (sec_status == SEC_I_COMPLETE_NEEDED)
				{
					authn_completed = true;
				}
				break;
			}
			default:
				break;
			}
		}
		return ctxt_handle;
	}

	CtxtHandle SchannelTLS::client_perform_handshake(CredHandle cred_handle, PWSocket transport, const char* host_name, bool verify_server_cert)
	{
		// TLS handshake algorithm.
		// 1. Call InitializeSecurityContext.
		//    The first call creates a security context.
		//    Subsequent calls update the security context.
		// 2. Check InitializeSecurityContext's return value.
		//    SEC_E_OK                     - Handshake completed, TLS tunnel ready to go.
		//    SEC_I_CONTINUE_NEEDED        - Success, keep calling InitializeSecurityContext (send).
		//    SEC_E_INCOMPLETE_MESSAGE     - Success, continue reading data from the server (recv).
		//    SEC_I_INCOMPLETE_CREDENTIALS - The server asked for client certs.
		// 3. Otherwise an error may have been encountered. Set an error state and return.
		// 4. Read data from the server (recv).

		CtxtHandle ctxt_handle = { 0 };
		if (!establish_client_security_context_first_stage(cred_handle, transport, host_name, ctxt_handle))
		{
			free_ctxt_handle(ctxt_handle);
		}
		if (!establish_client_security_context_second_stage(cred_handle, transport, host_name, verify_server_cert, ctxt_handle))
		{
			free_ctxt_handle(ctxt_handle);
		}
		return ctxt_handle;
	}

	static bool establish_client_security_context_first_stage(CredHandle cred_handle, PWSocket transport, const char* host_name, CtxtHandle& ctxt_handle)
	{
		SecBuffer secure_buffer_out[1] = { 0 };
		init_sec_buffer(secure_buffer_out[0], SECBUFFER_EMPTY, 0, NULL);

		SecBufferDesc secure_buffer_desc_out = { 0 };
		init_sec_buffer_desc(secure_buffer_desc_out, SECBUFFER_VERSION, 1, secure_buffer_out);
		Helper::DeferFunctionRAII free_buffers_deferred([&secure_buffer_desc_out]() { free_all_buffers(secure_buffer_desc_out); });

		/* Security request flags */
		DWORD dwFlags = ISC_REQ_USE_SUPPLIED_CREDS | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
			ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR |
			ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;
		SECURITY_STATUS sec_status = InitializeSecurityContextA(
			&cred_handle,
			NULL, // Must be null on first call
			(SEC_CHAR*)host_name,
			dwFlags,
			0,
			0,
			NULL, // Must be null on first call
			0,
			&ctxt_handle,
			&secure_buffer_desc_out,
			&dwFlags,
			NULL);
		if (sec_status != SEC_I_CONTINUE_NEEDED)
		{
			LOG_ERROR_A("[SchannelTLS] InitializeSecurityContext: %ld", sec_status);
			return false;
		}
		if (secure_buffer_out[0].pvBuffer && secure_buffer_out[0].cbBuffer > 0)
		{
			int bytes_sented = transport->tcp_send_data((const char*)secure_buffer_out[0].pvBuffer, secure_buffer_out[0].cbBuffer);
			if (bytes_sented <= 0)
			{
				LOG_ERROR_A("[SchannelTLS] tcp_write_data() failed! Error code: %d", bytes_sented);
				return false;
			}
		}
		return true;
	}

	static bool establish_client_security_context_second_stage(CredHandle cred_handle, PWSocket transport, const char* host_name, bool verify_server_cert, CtxtHandle& ctxt_handle)
	{
		int offset = 0;
		bool skip = false;
		auto in_buffer = std::make_unique<char[]>(TLS_MAX_RECORD_SIZE);
		do
		{
			int in_buffer_size = 0;
			if (!skip)
			{
				int bytes_received = transport->tcp_recv_data(in_buffer.get() + offset, TLS_MAX_RECORD_SIZE);
				if (bytes_received == 0)
				{
					LOG_ERROR_A("[SchannelTLS] Server disconnected socket!");
					return false;
				}
				if (bytes_received < 0)
				{
					LOG_ERROR_A("[SchannelTLS] tcp_read_data() failed! Error code: %d", bytes_received);
					return false;
				}
				in_buffer_size = bytes_received + offset;
			}
			else
			{
				in_buffer_size = offset;
			}
			skip = false;
			offset = 0;

			// Input buffer
			SecBuffer secure_buffer_in[4] = { 0 };
			init_sec_buffer(secure_buffer_in[0], SECBUFFER_TOKEN, in_buffer_size, in_buffer.get());
			init_sec_buffer(secure_buffer_in[1], SECBUFFER_EMPTY, 0, nullptr);
			init_sec_buffer(secure_buffer_in[2], SECBUFFER_EMPTY, 0, nullptr);
			init_sec_buffer(secure_buffer_in[3], SECBUFFER_EMPTY, 0, nullptr);

			SecBufferDesc secure_buffer_desc_in = { 0 };
			init_sec_buffer_desc(secure_buffer_desc_in, SECBUFFER_VERSION, 4, secure_buffer_in);

			// Output buffer
			SecBuffer secure_buffer_out[3] = { 0 };
			init_sec_buffer(secure_buffer_out[0], SECBUFFER_TOKEN, 0, nullptr);
			init_sec_buffer(secure_buffer_out[1], SECBUFFER_ALERT, 0, nullptr);
			init_sec_buffer(secure_buffer_out[2], SECBUFFER_EMPTY, 0, nullptr);

			SecBufferDesc secure_buffer_desc_out = { 0 };
			init_sec_buffer_desc(secure_buffer_desc_out, SECBUFFER_VERSION, 3, secure_buffer_out);
			Helper::DeferFunctionRAII free_buffers_deferred([&secure_buffer_desc_out]() { free_all_buffers(secure_buffer_desc_out); });

			/* Security request flags */
			DWORD dwFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
				ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR |
				ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;
			if (verify_server_cert)
			{
				// Used for manual validation in SSPI-based security contexts.
				dwFlags |= ISC_REQ_MANUAL_CRED_VALIDATION;
			}
			else
			{
				dwFlags |= ISC_REQ_USE_SUPPLIED_CREDS;
			}

			/* https://learn.microsoft.com/en-us/windows/win32/secauthn/manually-validating-schannel-credentials?redirectedfrom=MSDN */
			SECURITY_STATUS sec_status = InitializeSecurityContextA(
											&cred_handle,
											&ctxt_handle,
											NULL,
											dwFlags,
											0,
											0,
											&secure_buffer_desc_in,
											0,
											NULL,
											&secure_buffer_desc_out,
											&dwFlags,
											NULL);
			switch (sec_status)
			{
			case SEC_E_OK:
				// Successfully completed handshake. TLS tunnel is now operational.
				return true;
			case SEC_I_CONTINUE_NEEDED:
			{
				// Continue sending data to the server.
				const char* buffer = (const char*)secure_buffer_out[0].pvBuffer;
				unsigned long size = secure_buffer_out[0].cbBuffer;
				if (!buffer || size == 0)
				{
					return false;
				}
				while (size > 0)
				{
					int bytes_sented = transport->tcp_send_data(buffer, size);
					if (bytes_sented <= 0)
					{
						break;
					}
					buffer += bytes_sented;
					size -= bytes_sented;
				}
				// Fetch incoming data.
				if (secure_buffer_in[1].BufferType == SECBUFFER_EXTRA)
				{
					offset = secure_buffer_in[0].cbBuffer - secure_buffer_in[1].cbBuffer;
					MoveMemory(in_buffer.get(), in_buffer.get() + offset, secure_buffer_in[1].cbBuffer);
					offset = secure_buffer_in[1].cbBuffer;
					skip = true;
				}
				if (secure_buffer_in[1].BufferType == SECBUFFER_MISSING)
				{
					offset = 0;
				}
				break;
			}
			case SEC_E_INCOMPLETE_MESSAGE:
				// Need to read more bytes.
				offset = secure_buffer_in[0].cbBuffer;
				break;
			case SEC_I_INCOMPLETE_CREDENTIALS:
				LOG_ERROR_A("[SchannelTLS] Server requests client certificate (not supported here): %ld", sec_status);
				return false;
			default:
				LOG_ERROR_A("[SchannelTLS] InitializeSecurityContext: %ld", sec_status);
				return false;
			}
		}
		while (true);

		return true;
	}



	bool SchannelTLS::shutdown(CredHandle cred_handle, CtxtHandle ctxt_handle, PWSocket transport)
	{
		SECURITY_STATUS sec_status;
		DWORD dwShutdown = SCHANNEL_SHUTDOWN;
		SecBuffer close_buffer_in[1];
		init_sec_buffer(close_buffer_in[0], SECBUFFER_TOKEN, sizeof(dwShutdown), &dwShutdown);

		SecBufferDesc close_buffer_in_desc;
		init_sec_buffer_desc(close_buffer_in_desc, SECBUFFER_VERSION, 1, close_buffer_in);

		sec_status = ApplyControlToken(&ctxt_handle, &close_buffer_in_desc);
		if (sec_status != SEC_E_OK)
		{
			LOG_ERROR_A("[SchannelTLS] ApplyControlToken: %ld", sec_status);
			return false;
		}
		SecBuffer close_buffer_out[2];
		init_sec_buffer(close_buffer_out[0], SECBUFFER_TOKEN, 0, nullptr);
		init_sec_buffer(close_buffer_out[1], SECBUFFER_EMPTY, 0, nullptr);

		SecBufferDesc close_buffer_out_desc;
		init_sec_buffer_desc(close_buffer_out_desc, SECBUFFER_VERSION, 2, close_buffer_out);
		Helper::DeferFunctionRAII free_buffers_deferred([&close_buffer_out_desc]() { free_all_buffers(close_buffer_out_desc); });

		/* Security request flags */
		DWORD dwFlags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
			ISC_REQ_CONFIDENTIALITY | ISC_RET_EXTENDED_ERROR |
			ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM;
		sec_status = InitializeSecurityContextA(
			&cred_handle,
			&ctxt_handle,
			NULL,
			dwFlags,
			0,
			SECURITY_NATIVE_DREP,
			NULL,
			0,
			NULL,
			&close_buffer_out_desc,
			&dwFlags,
			NULL);
		if (sec_status != SEC_E_OK && sec_status != SEC_I_CONTEXT_EXPIRED)
		{
			LOG_ERROR_A("[SchannelTLS] InitializeSecurityContext: %ld", sec_status);
			return false;
		}
		if (close_buffer_out[0].pvBuffer && close_buffer_out[0].cbBuffer > 0)
		{
			// Send TLS close_notify
			int bytes_sented = transport->tcp_send_data((char*)close_buffer_out[0].pvBuffer, close_buffer_out[0].cbBuffer);
			if (bytes_sented <= 0)
			{
				LOG_ERROR_A("[SchannelTLS] tcp_write_data() failed! Error code: %d", bytes_sented);
				return false;
			}
		}
		return true;
	}


	int SchannelTLS::tls_read_data(CtxtHandle ctxt_handle, PWSocket transport, char* data, int len)
	{
		if (!data || len == 0)
		{
			return -1;
		}
		SecPkgContext_StreamSizes stream_sizes = get_stream_sizes(ctxt_handle);
		int total_bytes_readed = 0;
		while (len > 0)
		{
			int len_use = min(len, stream_sizes.cbMaximumMessage);
			{
				auto encrypted_buf = std::make_unique<char[]>(TLS_MAX_PACKET_SIZE);
				int bytes_received = transport->tcp_recv_data(encrypted_buf.get(), TLS_MAX_PACKET_SIZE);
				if (bytes_received <= 0)
				{
					LOG_ERROR_A("[SchannelTLS] tcp_read_data() failed! Error code: %d", bytes_received);
					return -1;
				}
				int decrypted_len = decrypt_data(ctxt_handle,
					stream_sizes,
					encrypted_buf.get(),
					bytes_received,
					data, len_use);
				if (decrypted_len == -1)
				{
					LOG_ERROR_A("[SchannelTLS] decrypt_data() failed!");
					return -1;
				}
				if (decrypted_len == SEC_E_INCOMPLETE_MESSAGE)
				{

				}
				total_bytes_readed += bytes_received;
			}
			data = (PCHAR)(data) + len_use;
			len -= len_use;
		}
		return total_bytes_readed;
	}

	int SchannelTLS::tls_write_data(CtxtHandle ctxt_handle, PWSocket transport, const char* data, int len)
	{
		if (!data || len == 0)
		{
			return -1;
		}
		SecPkgContext_StreamSizes stream_sizes = get_stream_sizes(ctxt_handle);
		int total_bytes_writed = 0;
		while (len > 0)
		{
			int len_use = min(len, stream_sizes.cbMaximumMessage);
			{
				auto encrypted_buf = std::make_unique<char[]>(TLS_MAX_PACKET_SIZE);
				int encrypted_len = encrypt_data(ctxt_handle,
					stream_sizes,
					data, len_use,
					encrypted_buf.get(),
					TLS_MAX_PACKET_SIZE);
				if (encrypted_len == -1)
				{
					LOG_ERROR_A("[SchannelTLS] encrypt_data() failed!");
					return -1;
				}
				int bytes_sented = transport->tcp_send_data(encrypted_buf.get(), encrypted_len);
				if (bytes_sented <= 0)
				{
					LOG_ERROR_A("[SchannelTLS] tcp_write_data() failed! Error code: %d", bytes_sented);
					return -1;
				}
				total_bytes_writed += bytes_sented;
			}
			data = (PCHAR)(data)+len_use;
			len -= len_use;
		}
		return total_bytes_writed;
	}



	SecPkgContext_StreamSizes SchannelTLS::get_stream_sizes(CtxtHandle ctxt_handle)
	{
		SecPkgContext_StreamSizes stream_sizes = { 0 };
		SECURITY_STATUS sec_status = QueryContextAttributesA(&ctxt_handle, SECPKG_ATTR_STREAM_SIZES, &stream_sizes);
		if (sec_status != SEC_E_OK)
		{
			LOG_ERROR_A("[SchannelTLS] ssl_get_stream_sizes() failed! QueryContextAttributes() returned error = %ld", sec_status);
		}
		return stream_sizes;
	}

	int SchannelTLS::encrypt_data(CtxtHandle security_context, SecPkgContext_StreamSizes stream_sizes, const void* in_buf, int in_len, void* out_buf, int out_len)
	{
		int min_out_len = in_len + stream_sizes.cbHeader + stream_sizes.cbTrailer;
		if (min_out_len > (int)stream_sizes.cbMaximumMessage)
		{
			LOG_ERROR_A("[SchannelTLS] Message is too long!");
			return SEC_E_INVALID_PARAMETER;
		}
		if (min_out_len > TLS_MAX_RECORD_SIZE)
		{
			LOG_ERROR_A("[SchannelTLS] Output buffer is too small!");
			return SEC_E_INSUFFICIENT_MEMORY;
		}
		auto encrypt_buf = std::make_unique<char[]>(out_len);

		SecBuffer secure_buffers[4] = { 0 };
		init_sec_buffer(secure_buffers[0], SECBUFFER_STREAM_HEADER, stream_sizes.cbHeader, encrypt_buf.get());
		init_sec_buffer(secure_buffers[1], SECBUFFER_DATA, in_len, encrypt_buf.get() + stream_sizes.cbHeader);
		init_sec_buffer(secure_buffers[2], SECBUFFER_STREAM_TRAILER, stream_sizes.cbTrailer, encrypt_buf.get() + stream_sizes.cbHeader + in_len);
		init_sec_buffer(secure_buffers[3], SECBUFFER_EMPTY, 0, nullptr);
		// Copy in_buf -> SECBUFFER_DATA
		if (secure_buffers[1].pvBuffer)
		{
			CopyMemory(secure_buffers[1].pvBuffer, in_buf, in_len);
		}
		SecBufferDesc secure_buffer_desc = { 0 };
		init_sec_buffer_desc(secure_buffer_desc, SECBUFFER_VERSION, 4, secure_buffers);

		SECURITY_STATUS sec_status = EncryptMessage(&security_context, 0, &secure_buffer_desc, 0);
		if (sec_status != SEC_E_OK)
		{
			LOG_ERROR_A("[SchannelTLS] EncryptMessage() returned error %ld", sec_status);
			return sec_status;
		}
		// HEADER + DATA + TRAILER
		int encrypt_buf_size = secure_buffers[0].cbBuffer + secure_buffers[1].cbBuffer + secure_buffers[2].cbBuffer;
		CopyMemory(out_buf, encrypt_buf.get(), min(encrypt_buf_size, out_len));
		return encrypt_buf_size;
	}

	int SchannelTLS::decrypt_data(CtxtHandle security_context, SecPkgContext_StreamSizes stream_sizes, const void* in_buf, int in_len, void* out_buf, int out_len)
	{
		int min_out_len = in_len - stream_sizes.cbHeader - stream_sizes.cbTrailer;
		if (min_out_len > (int)stream_sizes.cbMaximumMessage)
		{
			LOG_ERROR_A("[SchannelTLS] Message to is too long!");
			return SEC_E_INVALID_PARAMETER;
		}
		if (min_out_len > TLS_MAX_RECORD_SIZE)
		{
			LOG_ERROR_A("[SchannelTLS] Output buffer is too small!");
			return SEC_E_INSUFFICIENT_MEMORY;
		}
		auto decrypt_buf = std::make_unique<char[]>(in_len);

		SecBuffer secure_buffers[4] = { 0 };
		init_sec_buffer(secure_buffers[0], SECBUFFER_DATA, in_len, decrypt_buf.get());
		init_sec_buffer(secure_buffers[1], SECBUFFER_EMPTY, 0, nullptr);
		init_sec_buffer(secure_buffers[2], SECBUFFER_EMPTY, 0, nullptr);
		init_sec_buffer(secure_buffers[3], SECBUFFER_EMPTY, 0, nullptr);
		// Copy in_buf -> SECBUFFER_DATA
		if (secure_buffers[0].pvBuffer)
		{
			CopyMemory(secure_buffers[0].pvBuffer, in_buf, in_len);
		}
		SecBufferDesc secure_buffer_desc = { 0 };
		init_sec_buffer_desc(secure_buffer_desc, SECBUFFER_VERSION, 4, secure_buffers);

		SECURITY_STATUS sec_status = DecryptMessage(&security_context, &secure_buffer_desc, 0, NULL);
		if (sec_status != SEC_E_OK)
		{
			LOG_ERROR_A("[SchannelTLS] DecryptMessage() returned error %ld", sec_status);
			return sec_status;
		}
		// DATA
		int decrypt_buf_size = secure_buffers[1].cbBuffer;
		CopyMemory(out_buf, secure_buffers[1].pvBuffer, min(decrypt_buf_size, out_len));
		return decrypt_buf_size;
	}

	static void init_sec_buffer_desc(SecBufferDesc& secure_buffer_desc, unsigned long version, unsigned long num_buffers, SecBuffer* buffers)
	{
		secure_buffer_desc.ulVersion = version;
		secure_buffer_desc.cBuffers = num_buffers;
		secure_buffer_desc.pBuffers = buffers;
	}

	static void init_sec_buffer(SecBuffer& secure_buffer, unsigned long type, unsigned long len, void* buffer)
	{
		secure_buffer.BufferType = type;
		secure_buffer.cbBuffer = len;
		secure_buffer.pvBuffer = buffer;
	}

	static void free_all_buffers(SecBufferDesc& secure_buffer_desc)
	{
		for (unsigned long i = 0; i < secure_buffer_desc.cBuffers; ++i)
		{
			auto buffer = secure_buffer_desc.pBuffers[i].pvBuffer;
			if (buffer != nullptr)
			{
				FreeContextBuffer(buffer);
			}
		}
	}




}