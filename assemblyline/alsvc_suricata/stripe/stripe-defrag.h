void hexdump(char *data, unsigned int length){
	unsigned int i = 0;

	while(i < length){
	printf("%02x ", (unsigned char)data[i++] & '\xff');
	}
}

frag_hole_t *hole(guint16 start, guint16 end){
	// Creates a fragment hole record
	frag_hole_t *newhole = NULL;
	
	newhole=(frag_hole_t*)malloc(sizeof(frag_hole_t));
	if(newhole == NULL){
		printf("Error allocating memory for fragment hole data!\n");
		return(NULL);
	}
	newhole->start = start;
	newhole->end = end;
	newhole->next = NULL;
	newhole->prev = NULL;
	
	return(newhole);
}

frame_t *merge_fragment(fragment_detail_t *frag, fragment_list_t *fragmentlist){
	// RFC 815 fragment reassembly algorithm. If the fragment provided completes a frame
	// then it is returned, otherwise the fragment list is updated and NULL returned.
	frag_hole_t *cur = NULL, 
				*newhole = NULL,
				*destroyme = NULL;
	frame_t 	*frame = NULL;
	int			ihl = (frag->data[0] & '\x0f') * 4;
	
	for(cur = fragmentlist->holes; cur != NULL; cur = cur->next){	// step 1
		if(frag->start > cur->end) continue;						// step 2 - fragment after current hole
		if(frag->end < cur->start) continue;						// step 3 - frament precedes current hole
		
		if(fragmentlist->holes == cur){								// step 4 - fragment overlaps hole, delete hole
			fragmentlist->holes = cur->next;
		} else {
			cur->prev->next = cur->next;
		}
		if(cur->next != NULL){
			cur->next->prev = cur->prev;
		}
		destroyme = cur;
		
		if(frag->start > cur->start){								// step 5 - fragment not at beginning of hole, create smaller hole before
			newhole = hole(cur->start, frag->start - 1);
			newhole->next = fragmentlist->holes;
			if(fragmentlist->holes != NULL){
				fragmentlist->holes->prev = newhole;
			}
			fragmentlist->holes = newhole;
		}
		
		if((frag->end < cur->end) && (frag->more == MOREFRAGS)){	// step 6 - fragment not at end of hole and there are more to come, create smaller hole after
			newhole = hole(frag->end + 1, cur->end);
			newhole->next = fragmentlist->holes;
			if(fragmentlist->holes != NULL){
				fragmentlist->holes->prev = newhole;
			}
			fragmentlist->holes = newhole;
		}
		
		// step 7 - inspect next hole
	}

	// If we removed an entry, free the memory
	if(destroyme != NULL){
		free(destroyme);
		destroyme = NULL;
	}
	
	// Copy data in
	memcpy(fragmentlist->data + frag->start, frag->data+ihl, frag->end - frag->start);
	
	// If this is the first fragment then grab the IP header
	if(frag->start == 0){
		fragmentlist->header = malloc(ihl);
		if(fragmentlist->header == NULL){
			printf("Error, unable to allocate memory for IP header reassembly!\n");
			return(NULL);
		}
		memcpy(fragmentlist->header, frag->data, ihl);
	}
	
	// If no more fragments then set data size
	if(frag->more == 0){
		fragmentlist->size = frag->end;
	}
	
	// If there are no holes left then our frame is complete
	// Build up the frame template ready to return
	if(fragmentlist->holes == NULL){
		frame = malloc(sizeof(frame_t));
		if(frame == NULL){
			printf("Error: could not allocate memory for defragmented frame!\n");
			return(NULL);
		}
		frame->payload = malloc(ihl+fragmentlist->size);
		memcpy(frame->payload, fragmentlist->header, ihl);
		memcpy(frame->payload + ihl, fragmentlist->data, fragmentlist->size);
		memcpy(frame->payload + 2, &fragmentlist->size, 2);	// Adjust total length
		memcpy(frame->payload + 6, "\x00\x00",2);			// Reset fragment info
		frame->plen = fragmentlist->size + ihl;
		memcpy(frame->etype, "\x08\x00", 2);
		frame->fragment = 0;
	}

	free(frag->data);
        free(frag);

	// Return a frame if we got one or NULL otherwise
	return(frame);
}

frame_t *insert_fragment(fragment_detail_t *frag, fragment_list_t **fragments, char *ipinfo){
	fragment_list_t *cur = NULL,
					*prev = NULL;
	frame_t			*frame = NULL;
	
	// If no other entries exist, create one and make it the head of the list
	if(*fragments == NULL){
		cur = (fragment_list_t*)malloc(sizeof(fragment_list_t));
		if(cur == NULL){
			printf("Error: could not allocate memory for fragment list!\n");
			return(NULL);
		}
		
		cur->data = (char*)malloc(65535);
		if(cur->data == NULL){
			printf("Error: could not allocate working memory for fragment rebuild!\n");
			free(cur->ipinfo);
			free(cur);
			return(NULL);
		}
		
		cur->ipinfo = ipinfo;
		cur->holes = hole(0, 65535);
		cur->header = NULL;
		cur->next = NULL;
		*fragments = cur;
		return(merge_fragment(frag, cur));	
	}
	
	// Otherwise, look for a fragment entry with the same IP info
	cur = *fragments;
	// Work through the list until we find a fragment list with the same IP info
	while(cur != NULL){
		if(memcmp(cur->ipinfo, ipinfo, 6) == 0){
			// Found a match, add the frame detail
			frame = merge_fragment(frag, cur);

			// If we got a completed frame back...
			if(frame != NULL){
				// Change references to point past this item
				if(prev == NULL){
					*fragments = cur->next;
				} else {
					prev->next = cur->next;
				}
				// Clean up unreferenced memory
				free(cur->ipinfo);
				free(cur->header);
				free(cur->data);
				free(cur);
			}
			// Return a frame if we got one or NULL otherwise
			return(frame);
		}	
		prev = cur;
		cur = cur->next;
	}
	
	// If we got here then our IP info didn't match anything in the list.
	// Create a new entry and populate it
	cur = malloc(sizeof(fragment_list_t));
	if(cur == NULL){
		printf("Error: could not allocate memory for fragment list!\n");
		return(NULL);
	}
	cur->ipinfo = ipinfo;
	cur->data = (char*)malloc(65535);
	if(cur->data == NULL){
		printf("Error: could not allocate working memory for fragment rebuild!\n");
		free(cur->ipinfo);
		free(cur);
		return(NULL);
	}
	cur->holes = hole(0, 65535);
	cur->header = NULL;
	cur->next = NULL;
	
	// Add this entry to the end of the list
	prev->next = cur;
	return(merge_fragment(frag, cur));
}	

frame_t *handle_ipv4_fragment(char *data, unsigned int length, frame_t *frame, fragment_list_t **fragments){
	fragment_detail_t *frag = NULL;
	int 	total_length = 0,
			header_length = 0;
	char 	*ipinfo = NULL;
		
	// Calculate the lengths from the IPv4 header
	total_length = (256 * (unsigned char)data[2]) + (unsigned char)data[3];
	header_length = 4 * ((unsigned char)data[0] & '\x0f');
		
	// Create the fragment record
	frag = (fragment_detail_t*)malloc(sizeof(fragment_detail_t));
	if(frag == NULL){
		printf("Error: could not allocate memory for re-assembly!\n");
		return(NULL);
	}
	
	// Populate the fragment record
	frag->start = 8 * ((256 * ((unsigned char)data[6] & '\x1f')) + (unsigned char)data[7]);
	frag->end = frag->start + total_length - header_length;
	frag->data = malloc(total_length);
	if(frag->data == NULL){
		printf("Error: could not allocate memory for fragment mirror\n");
		free(frag);
		return(NULL);
	}
	
	// Sanity check the length field vs. captured data length
	if(total_length > length){
		printf("Error: truncated packet fragment!\n");
		free(frag);
		return(NULL);
	}
	
	// Populate the IP info
	ipinfo = malloc(10);
	if(ipinfo == NULL){
		printf("Error: unable to allocate memory for IP info\n");
		free(frag);
		return(NULL);
	}
	memcpy(ipinfo, data + 4, 2);		// IPID
	memcpy(ipinfo + 2, data + 12, 8);	// Source & Destination
	
	// Copy the data into the fragment record
	memcpy(frag->data, data, total_length);
		
	// Populate the more fragments indicator
	frag->more = (data[6] & MOREFRAGS);

	// Insert this fragment into the list of lists of fragments, if it completes a frame then return it
	return(insert_fragment(frag, fragments, ipinfo));
}

frame_t *reassemble(char *data, unsigned int length, char type, frame_t *frame, fragment_list_t **fragments){
	if(type != ETHERNET){
		printf("Warning: Trying to re-assemble non-Ethernet type!\n");
		return(NULL);
	}
	if(length < 14){
		printf("Warning: truncated frame discarded!\n");
		return(NULL);
	}
	if(data == NULL){
		printf("Warning: trying to re-assemble null frame data!\n");
		return(NULL);
	}
	
	// Populate the frame header and etype
	frame->ether = data;
	memcpy(frame->etype, data+12, 2);
	frame->plen = length - 14;
	
	// For non-IP, simply return the frame
	if(memcmp(data+12, "\x08\x00",2) != 0){
		frame->payload = data + 14;
		return(frame);
	}
	
	// For non-fragments, simply return the frame
	if(((data[20] & '\x3f') | data[21]) == 0){
		frame->payload = data + 14;
		return(frame);
	}
	
	// For fragments, attempt to re-assemble	
	frame = handle_ipv4_fragment(data+14, length-14, frame, fragments);
	if(frame != NULL){
		frame->ether = data;
	}
	return(frame);
}
