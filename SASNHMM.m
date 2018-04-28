clc
clear all
close all
%完成基于攻击面NHMM的MTD有效性评估工作
%% parameter initialize
%system parameter initialize
%nodes information
Host_num = 3;
Vuln_host_num = 1;
Vuln_host_id = 1;
Obj_host_num = 1;
Obj_host_id = 1;
Link_matrix = [1,1,1;0,1,0;0,0,1];
IP_segment = 'c';
%defense states initialize
PCS.ospool = {'W','U','R'};
PCS.servicepool = {'A','N','I'};
PCS.ip = 200;
PCS.os = size(PCS.ospool,2);
PCS.service = size(PCS.servicepool,2);
PCS.mem = 2^16-1;
FRQ.ip = 100;
FRQ.os = 500;
FRQ.service = 300;
STRA = 'random';% two mutation stragey, pure random and max-diff
% STRA
%Vul states got from CVE (Impact scores are average value)
VUL.os.W.num = 533;
VUL.os.U.num = 658;
VUL.os.R.num = 153;
VUL.os.W.exp = 6.0;
VUL.os.U.exp = 8.0;
VUL.os.R.exp = 8.4;
VUL.service.I.num = 1;
VUL.service.A.num = 16;
VUL.service.N.num = 1;
VUL.service.I.exp = 4.9;
VUL.service.A.exp = 9.5;
VUL.service.N.exp = 8.6;
INT.os.W = 7.4;
INT.os.U = 5.2;
INT.os.R = 6.1;
INT.service.I = 6.4;
INT.service.A = 3.5;
INT.service.N = 2.9;
%offense state initialize
ATT.obj = 'data-exf'; % data-exf, inf-dd, DoS;
ATT.abi = 0;% 0为low，0.5为medium，1为high
ATT.pr = 'admin';
%NHMM model states initialize
% P.abst = []; %
% P.pare = [];
% P.att = [];
% P.obj = [];
% A.abst = [];
% A.pare = [];
% A.att = [];
% A.obj = [];
% B.pare = [];
% B.att = [];
% B.obj = [];

%% HHMM Structure
q(:,:,1) = [1 0 0 0 0 0 0 0 0 0;        % 1 State, 2 Endstate
    1 1 1 2 0 0 0 0 0 0;
    1 1 1 2 1 1 2 1 1 2;];

q(:,:,2) = [4 0 0 0 0 0 0 0 0 0;        % num is set to be the number of child nodes
    4 3 3 0 0 0 0 0 0 0;
    0 0 0 0 0 0 0 0 0 0;];

alphabet = 1:8;
%% matrix initialize
%[y x] = find(q(:,:,1)==1 & q(:,:,2)==0);
[prodY, prodX] = find(q(:,:,1)==1 & q(:,:,2)==0); % get all production nodes
[allY, allX] = find(q(:,:,1)==1); % get all nodes expect end-node
[intY, intX] = find(q(:,:,2)~=0); % get all nodes that have child nodes
% Vertical Transitions
PI = zeros(size(q,2),size(q,2),size(q,1)-1); % PI matrix
for i=1:length(allX)
    if allY(i)~=1
        parent_i = find(cumsum(q(allY(i)-1,:,2))>=allX(i),1);
        %         if allX(i) == 1 || allX(i) == 1+q(2,1,2) || allX(i) == 1+sum(q(2,1:2,2))
        PI(parent_i,allX(i),allY(i)-1)= 1;
        %         end
    end
end

% Horizontal Transitions
A = zeros(size(q,2),size(q,2),size(q,1)-1);
for i=1:length(allX)
    if allY(i)~=1
        parent_i = find(cumsum(q(allY(i)-1,:,2))>=allX(i),1);
        jArray = find(PI(parent_i,:,allY(i)-1)~=0);
        jArray = [jArray jArray(end)+1];
        A(allX(i),jArray,allY(i)-1)= 1;
    end
end
% Emissions
for i=1:length(prodX);
    
    B(prodY(i),prodX(i),1:length(alphabet)) = 1;
end;

%% get MEAS form *.mat or by func ias2eas.m
load('MEAS_foc.mat')

%% state calculate
stop = 1;
ATT.win = 1;
while stop
    % last, we update the matrix of trans and product\
    
    if ATT.win
        stop = 0;
    end
end


