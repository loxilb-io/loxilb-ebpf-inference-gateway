/*
 * Copyright (c) 2022 NetLOX Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * loxilb_kv_tcp_stub.c -- TCP transport stub.
 *
 * TCP is POSIX and always available (not DOCA-dependent).
 * This stub exists only for Makefile pattern consistency with other
 * stub files.  It is intentionally empty because loxilb_kv_tcp.o is
 * built unconditionally via COMMON_OBJS in both HAVE_DOCA and stub
 * build modes.
 *
 * All TCP transport symbols (llb_kv_tcp_ops, llb_kv_recv_chunk) are
 * provided by loxilb_kv_tcp.c regardless of DOCA availability.
 */

/* Intentionally empty -- see loxilb_kv_tcp.c */
