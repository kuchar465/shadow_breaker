#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <stdint.h>

#include <sys/sysinfo.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <assert.h>
#include <string.h>
#include <crypt.h>


char * hash = "";
char * salt = "";
char * passwords = "";
int flag = 1;
int per = 0;
int fullper;
int threads=0;
int longestPass=0;
struct stat statbufPass;
struct stat statbufHash;
pthread_mutex_t lock;


char* hash2(char* password, char* salt){
	char* tmp = malloc(sizeof(char)*(strlen(salt)+4));
    strcat(tmp, "$6$");
	strcat(tmp, salt);
    struct crypt_data data;
    data.initialized = 0;
	char* hashVal = crypt_r(password, tmp, &data);
	free(tmp);
	return hashVal;
}

struct stoper {
    int start;
    int stop;
};

void percentageUpdate(int value){
    pthread_mutex_lock(&lock);
    per+=value;
    printf("\r%d%%",per*100/fullper);
    fflush(stdout);
    pthread_mutex_unlock(&lock);
    
}

void readHash(char * hashFile){
    char * smap1;
    int fd1 = open(hashFile, O_RDONLY);
    if(fd1 > 0){
        int res2 = fstat(fd1, &statbufHash);
    	if(res2 == 0){
            smap1 = mmap(NULL, statbufHash.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd1, 0);
            if(smap1 != NULL ){
                hash=smap1;
                for(int i=0;i<2;i++)
                    salt = strtok_r(hash, "$", &hash);
                munmap(hash, statbufHash.st_size);
                hash = mmap(NULL, statbufHash.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd1, 0); 
                close(fd1);
            }
        }
    }
}

void* threadFunction(void* a){
	struct stoper *border = a;
	char* password = malloc(sizeof(char)*longestPass);
	int z=0;
    int before = 0;
	for(int i=border->start; i<border->stop; i++){
        if(flag==0){
            break;
        }
		if(passwords[i] != '\n'){
			password[z]=passwords[i];
			z++;
            if(flag==0){
                break;
            }
		}
		else{
			char* check = hash2(password, salt);
			if(strcmp(check, hash)==0){
                flag = 0;
                percentageUpdate(1);
				printf("\n%s - ",password);
                printf("found\n");
				break;	
			}
			bzero(password, longestPass);
			z=0;
            if(flag!=0){
            percentageUpdate(1);
            }
            before=i;
		}	
	}
    free(password);	
}

int main(int argc, char **argv){

    int ret;
    char * hashFile, * dict;
    pthread_mutex_init(&lock, NULL);
    int amtOfProcesors = get_nprocs();
    char *smap2;
    int passMax = 0;
    int passwordAmount = 0;
    
   
    while ((ret = getopt (argc, argv, "h:d:t:")) != -1)
        switch (ret) {
            case 'h':
                hashFile = optarg;
                readHash(hashFile);
            break;
            case 'd':
                dict = optarg;
                int fd2 = open(dict, O_RDONLY);
                if (fd2 > 0){
                    int res = fstat(fd2, &statbufPass);
                    if(res == 0){
                        char* smap2 = mmap(NULL, statbufPass.st_size, PROT_READ, MAP_SHARED, fd2, 0);
                        if(smap2 != NULL && close(fd2)==0){
                            passwords=smap2;
                            int tmp = 0;
                            for(int i=0; passwords[i]!='\0'; i++){
                                if(passwords[i]=='\n'){
                                    passwordAmount++;
                                    if(passwordAmount==1000){
                                        passMax = i;
                                    }
                                    if(tmp>longestPass){
                                        longestPass=tmp;
                                    }
                                    tmp=0;
                                }
                                tmp++;  
                            }
                        }
                    }
                }   
            break;
            case 't':
                threads = atoi(optarg);
            break;
        }
    if(threads>0){
        if(amtOfProcesors<threads)
            threads=amtOfProcesors;

        struct stoper stopers[threads];
        pthread_t ArrayOfThreads[threads];
        fullper = passwordAmount;
        
        int bitLoc = (int)((float)statbufPass.st_size/(float)threads);

        
        int stop = 0;
	    for(int i=0; i<threads; i++){
		    int start = stop;
            stop=(i+1)*bitLoc;

            while(passwords[stop]!='\n' && passwords[stop]!='\0')
                stop++;
            if(passwords[start]=='\n')
                start++;
            stopers[i].start=start;
            stopers[i].stop=stop+1;

            pthread_create(&ArrayOfThreads[i], NULL, threadFunction, &stopers[i]);
            start = stop;
	    }
        for (int i=0;i<threads;i++)
		    pthread_join(ArrayOfThreads[i], NULL);
        
    
        if(flag==1){
            printf("\nnothing found\n");
        }
    }
    else{
        fullper = passwordAmount;
        struct timespec start;
        struct timespec stopt;
        int bitLoc;
        for(int i=1; i<=amtOfProcesors;i++){
            threads = i;
            clock_gettime(CLOCK_MONOTONIC, &start);
            struct stoper stopers[i];
            pthread_t ArrayOfThreads[i];

            if(passMax>0)
                bitLoc = (int)((float)passMax/(float)threads);
            else
                bitLoc = (int)((float)statbufPass.st_size/(float)threads);
                //printf("%d %d\n", bitLoc, passMax);
            int stop = 0;
            
	        for(int j=0; j<i; j++){
		        int start = stop;
                stop=(j+1)*bitLoc;
                //printf("%d\n", start);
                
                while(passwords[stop]!='\0' && passwords[stop]!='\n'){ 
                    stop++;
                }
                
                if(passwords[start]=='\n')
                    start++;
                    
                stopers[j].start=start;
                stopers[j].stop=stop+1;
                
                pthread_create(&ArrayOfThreads[j], NULL, threadFunction, &stopers[j]);
                start = stop;
	        }
            for (int j=0;j<i;j++)
		        pthread_join(ArrayOfThreads[j], NULL);
            per = 0;
            if(flag==1){
                printf("\nnothing found\n");
            }
            flag = 1;
            clock_gettime(CLOCK_MONOTONIC, &stopt);
            printf("time: %f threads: %d\n", (double)(stopt.tv_sec - start.tv_sec ) + (double)( stopt.tv_nsec - start.tv_nsec )/ (double)1000000000, i);
            printf("-----------------------\n");
        }
    }

    munmap(hash, statbufHash.st_size);
    munmap(passwords, statbufHash.st_size);
    pthread_mutex_destroy(&lock);


    return 0;
}